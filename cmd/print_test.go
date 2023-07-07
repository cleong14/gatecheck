package cmd

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"testing"
)

func Test_PrintCommand(t *testing.T) {
	config := CLIConfig{NewAsyncDecoderFunc: AsyncDecoderFunc}
	t.Parallel()

	t.Run("semgrep", func(t *testing.T) {
		f := MustOpen(semgrepTestReport, t)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "WARNING") == false {
			t.Fatal("'WARNING' not contained in", out)
		}
	})
	t.Run("grype", func(t *testing.T) {
		f := MustOpen(grypeTestReport, t)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "debian") == false {
			t.Fatal("'debian' not contained in", out)
		}
	})
	t.Run("gitleaks", func(t *testing.T) {
		f := MustOpen(gitleaksTestReport, t)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "jwt") == false {
			t.Fatal("'jwt' not contained in", out)
		}
		t.Log(out)
	})
	t.Run("cyclonedx", func(t *testing.T) {
		f := MustOpen(cyclonedxTestReport, t)
		out, err := Execute("print "+f.Name(), config)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "library") == false {
			t.Fatal("'Library' not contained in", out)
		}
		t.Log(out)
	})

	t.Run("multiple-files-and-piped-input", func(t *testing.T) {
		t.Run("success", func(t *testing.T) {
			f1 := MustOpen(grypeTestReport, t)
			f2 := MustOpen(semgrepTestReport, t)
			f3 := MustOpen(gitleaksTestReport, t)
			config := CLIConfig{NewAsyncDecoderFunc: AsyncDecoderFunc, PipedInput: f3}
			commandString := fmt.Sprintf("print %s %s", f1.Name(), f2.Name())
			out, err := Execute(commandString, config)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out, "debian") == false {
				t.Fatal("'debian' not contained in", out)
			}
			if strings.Contains(out, "WARNING") == false {
				t.Fatal("'WARNING' not contained in", out)
			}
			if strings.Contains(out, "jwt") == false {
				t.Fatal("'jwt' not contained in", out)
			}
			t.Log(out)
		})
	})

	t.Run("bad-file", func(t *testing.T) {
		badFile := fileWithBadPermissions(t)
		config := CLIConfig{NewAsyncDecoderFunc: AsyncDecoderFunc}

		if _, err := Execute("print "+badFile, config); errors.Is(err, ErrorFileAccess) != true {
			t.Fatal("Expected error for bad file, got", err)
		}
	})

	t.Run("unsupported-file", func(t *testing.T) {
		b := make([]byte, 1000)
		randomFile := path.Join(t.TempDir(), "random.file")
		if err := os.WriteFile(randomFile, b, 0664); err != nil {
			t.Fatal(err)
		}

		config := CLIConfig{NewAsyncDecoderFunc: AsyncDecoderFunc}

		if _, err := Execute("print "+randomFile, config); err != nil {
			t.Fatal(err)
		}
	})

}
