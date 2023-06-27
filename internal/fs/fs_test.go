package fs

import (
	"os"
	"path"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
)

func TestReadFile(t *testing.T) {
	t.Run("successful-read", func(t *testing.T) {
		decoder := artifact.NewGrypeReportDecoder()
		_, err := ReadFile("../../test/grype-report.json", decoder)
		if err != nil {
			t.Fatal(err)
		}
		report, err := decoder.Decode()
		if err != nil {
			t.Fatal(err)
		}
		matches := len(report.(*artifact.GrypeScanReport).Matches)
		if matches < 10 {
			t.Fatalf("want: >10 got: %d", matches)
		}
	})

	t.Run("bad-read", func(t *testing.T) {
		decoder := artifact.NewGrypeReportDecoder()
		_, err := ReadFile("nonexistingfile", decoder)
		if err == nil {
			t.Fatal("want error for non existing file")
		}
	})

	t.Run("bad-permissions", func(t *testing.T) {
		decoder := artifact.NewGrypeReportDecoder()
		_, err := ReadFile(fileWithBadPermissions(t), decoder)
		if err == nil {
			t.Fatal("want error for bad file permissions")
		}
	})
}

func TestReadDecodeFile(t *testing.T) {

	t.Run("bad-file", func(t *testing.T) {
		_, err := ReadDecodeFile("nonexistingfile", artifact.NewGrypeReportDecoder())
		if err == nil {
			t.Fatal("want error for non existing file")
		}
	})

	t.Run("successful", func(t *testing.T) {
		report, err := ReadDecodeFile("../../test/grype-report.json", artifact.NewGrypeReportDecoder())
		if err != nil {
			t.Fatal(err)
		}
		grypeReport, ok := report.(*artifact.GrypeScanReport)
		if !ok {
			t.Fatalf("invalid type %T", report)
		}
		matches := len(grypeReport.Matches)
		if matches < 10 {
			t.Fatalf("want: >10 got: %d", matches)
		}
	})
}

func fileWithBadPermissions(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file")
	f, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Chmod(0000); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	return n
}
