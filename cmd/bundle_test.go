package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	archive "github.com/gatecheckdev/gatecheck/pkg/archive"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestExtractCmd(t *testing.T) {
	type ObjA struct {
		ValueA int `json:"value_a"`
	}
	type ConfigA struct {
		ValueA int `yaml:"value_a"`
	}

	buf := new(bytes.Buffer)
	objA := &ObjA{15}
	json.NewEncoder(buf).Encode(objA)

	bundle := archive.NewBundle()
	bundle.Artifacts["mock_artifact.json"] = buf.Bytes()

	tempBundleFilename := path.Join(t.TempDir(), "bundle.gatecheck")

	f, _ := os.Create(tempBundleFilename)
	_ = archive.NewEncoder(f).Encode(bundle)
	f.Close()

	t.Run("success-extract", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle extract --label %s %s", "mock_artifact.json", tempBundleFilename)
		out, err := Execute(commandString, CLIConfig{})
		if err != nil {
			t.Log(out)
			t.Fatal(err)
		}
		f := MustOpen(tempBundleFilename, t.Fatal)
		b, err := new(archive.Decoder).DecodeFrom(f)
		if err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)

		decoder := gce.NewJSONWriterDecoder[ObjA]("Mock Obj A", func(*ObjA) error { return nil })

		asyncDecoder := new(gce.AsyncDecoder).WithDecoders(decoder)
		archive.NewPrettyWriter(buf).WithAsyncDecoder(asyncDecoder).Encode(b.(*archive.Bundle))
		t.Log(buf.String())
		if !strings.Contains(buf.String(), "Mock Obj A") {
			t.Fatal("want: Mock Obj A in output")	
		}

	})

	t.Run("file-access-error", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle extract --label %s %s", "mock_artifact.json", fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if !errors.Is(err, ErrorFileAccess) {
			t.Fatal(err)
		}
	})
	t.Run("file-bad-encoding", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle extract --label %s %s", "mock_artifact.json", fileWithBadJSON(t))
		_, err := Execute(commandString, CLIConfig{})
		if !errors.Is(err, ErrorEncoding) {
			t.Fatal(err)
		}
	})
	t.Run("file-bad-key", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle extract --label %s %s", "", tempBundleFilename)
		_, err := Execute(commandString, CLIConfig{})
		if !errors.Is(err, ErrorUserInput) {
			t.Fatal(err)
		}
	})
}

func TestNewBundleCmd(t *testing.T) {

	t.Run("file-access-error", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		commandString := fmt.Sprintf("bundle -o %s %s", outFile, fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-output-file", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle -o %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		commandString := fmt.Sprintf("bundle -vo %s %s", fileWithBadJSON(t), fileWithBadJSON(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
	})

	t.Run("bad-permission", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		commandString := fmt.Sprintf("bundle -vo %s %s", outFile, fileWithBadPermissions(t))
		_, err := Execute(commandString, CLIConfig{})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("success", func(t *testing.T) {
		outFile := path.Join(t.TempDir(), "bundle.gatecheck")
		targetFile := path.Join(t.TempDir(), "random-1.file")
		b := make([]byte, 1000)

		_, _ = rand.Read(b)
		if err := os.WriteFile(targetFile, b, 0664); err != nil {
			t.Fatal(err)
		}
		commandString := fmt.Sprintf("bundle -vo %s %s", outFile, targetFile)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 2})
		if err != nil {
			t.Fatal(err)
		}

		// Check bundle for the artifact
		postOutFile := MustOpen(outFile, t.Fatal)

		obj, err := new(archive.Decoder).DecodeFrom(postOutFile)
		if err != nil {
			t.Fatal(err)
		}

		bun, ok := obj.(*archive.Bundle)
		if !ok {
			t.Fatalf("got type %T", obj)
		}

		genericBytes, ok := bun.Artifacts["random-1.file"]
		if !ok {
			t.Fatal("Could not extract generic file")
		}

		if len(genericBytes) != 1000 {
			t.Fatal("Invalid decoded file size")
		}

		t.Run("print-test", func(t *testing.T) {
			commandString := fmt.Sprintf("print %s", outFile)
			output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 2})
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(output, "random-1.file") != true {
				t.Log(output)
				t.Fatal("unexpected content")
			}
		})

		t.Run("existing-bundle", func(t *testing.T) {
			secondFile := path.Join(t.TempDir(), "random-2.file")
			b := make([]byte, 2000)
			_, _ = rand.Read(b)
			if err := os.WriteFile(secondFile, b, 0664); err != nil {
				t.Fatal(err)
			}
			commandString := fmt.Sprintf("bundle -vo %s %s", outFile, secondFile)
			output, err := Execute(commandString, CLIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(output)
		})

		t.Run("empty-file", func(t *testing.T) {
			emptyFile := path.Join(t.TempDir(), "empty.file")
			if err := os.WriteFile(emptyFile, []byte{}, 0664); err != nil {
				t.Fatal(err)
			}
			commandString := fmt.Sprintf("bundle -vo %s %s", outFile, emptyFile)
			output, err := Execute(commandString, CLIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(output)
		})

		t.Run("allow-missing", func(t *testing.T) {
			someFile := path.Join(t.TempDir(), "some.file")

			commandString := fmt.Sprintf("bundle -mvo %s %s", outFile, someFile)
			output, err := Execute(commandString, CLIConfig{})
			if err != nil {
				t.Fatal(err)
			}
			t.Log(output)
		})
	})
}
