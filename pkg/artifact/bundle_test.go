package artifact

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewBundle(t *testing.T) {
	t.Run("without-config", func(t *testing.T) {

		art, _ := NewArtifact("some-artifact.txt", strings.NewReader("some content"))
		bundle := NewBundle(art)
		v, ok := bundle.Artifacts["some-artifact.txt"]
		if !ok {
			t.Fatalf("want artifact in bundle, got %+v", bundle)
		}
		if v.Type != TypeGeneric {
			t.Fatal("want generic, got", v.Type)
		}
		if string(v.Content) != "some content" {
			t.Fatalf("want 'some-content' got '%s'", string(v.Content))
		}
	})

	t.Run("with-config", func(t *testing.T) {
		art1, _ := NewArtifact("some-artifact.txt", strings.NewReader("some content"))
		configReader, _ := NewConfigReader(NewConfig())
		art2, _ := NewArtifact("gatecheck.yaml", configReader)
		if art2.Type != TypeGatecheckConfig {
			t.Fatalf("want %s, got %s", string(TypeGatecheckConfig), art2.Type)
		}
		bundle := NewBundle(art1, art2)

		if bundle.config == nil {
			t.Fatal("want config, got nil")
		}
	})

}

func TestBundleReader(t *testing.T) {
	grypeArtifact, _ := NewArtifact("grype-report.json", bytes.NewReader(MustReadFile("../../test/grype-report.json", t.Fatal)))
	semgrepArtifact, _ := NewArtifact("semgrep-report.json", bytes.NewReader(MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)))
	bundle := NewBundle(grypeArtifact, semgrepArtifact)

	reader, err := NewBundleReader(bundle)
	if err != nil {
		t.Fatal(err)
	}

	tempBuffer := new(bytes.Buffer)
	if _, err := reader.WriteTo(tempBuffer); err != nil {
		t.Fatal(err)
	}

	writer := new(BundleWriter)
	if _, err := writer.ReadFrom(tempBuffer); err != nil {
		t.Fatal(err)
	}
	v, err := writer.Decode()
	if err != nil {
		t.Fatal(err)
	}

	decodeBundle, ok := v.(*Bundle)
	if !ok {
		t.Fatal("decoded bundle is not a *Bundle")
	}

	if _, ok := decodeBundle.Artifacts["grype-report.json"]; !ok {
		t.Fatalf("Want decoded bundle, got %+v", decodeBundle)
	}

	wantDigest := bundle.Artifacts["grype-report.json"].DigestString()
	gotDigest := decodeBundle.Artifacts["grype-report.json"].DigestString()

	if gotDigest != wantDigest {
		t.Fatalf("want: %s got: %s", wantDigest, gotDigest)
	}
}

func TestWork(t *testing.T) {
	bundle := &Bundle{Version: "1", Artifacts: make(map[string]Artifact)}

	a, _ := NewArtifact("one", bytes.NewBufferString("content for one"))

	bundle.Artifacts[a.Label] = a

	r, err := NewBundleReader(bundle)
	if err != nil {
		t.Fatal(err)
	}
	buf := new(bytes.Buffer)

	if _, err := io.Copy(buf, r); err != nil {
		t.Fatal(err)
	}

	bundleWriter := new(BundleWriter)
	if _, err := buf.WriteTo(bundleWriter); err != nil {
		t.Fatal(err)
	}

	_, err = bundleWriter.Decode()
	if err != nil {
		t.Fatal(err)
	}

}
