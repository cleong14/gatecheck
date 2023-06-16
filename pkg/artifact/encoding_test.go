package artifact

import (
	"bytes"
	"context"
	"testing"
)

func TestAsyncDecoder_Grype(t *testing.T) {
	grypeBytes := MustReadFile("../../test/grype-report.json", t.Fatal)

	decoder := new(AsyncDecoder).WithDecoders(NewGrypeReportDecoder())

	_, err := decoder.ReadFrom(bytes.NewReader(grypeBytes))
	if err != nil {
		t.Fatal(err)
	}
	a, err := decoder.Decode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", a.(*GrypeScanReport).Descriptor)
}

func TestAsyncDecoder_Semgrep(t *testing.T) {
	b := MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)

	decoder := new(AsyncDecoder).WithDecoders(NewSemgrepReportDecoder())

	_, err := decoder.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	a, err := decoder.Decode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Semgrep Errors: %d", len(a.(*SemgrepScanReport).Errors))
}

func TestAsyncDecoder_Config(t *testing.T) {
	b := MustReadFile("../../test/gatecheck.yaml", t.Fatal)

	decoders := StandardDecoders()
	decoder := new(AsyncDecoder).WithDecoders(decoders...)

	_, err := decoder.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	a, err := decoder.Decode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Config Version: %s", a.(*Config).Version)
	t.Log(GatecheckTypeID(a))
}

func TestAsyncDecoder_Multi(t *testing.T) {
	b := MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)

	decoder := new(AsyncDecoder).WithDecoders(NewGrypeReportDecoder(), NewSemgrepReportDecoder())

	_, err := decoder.ReadFrom(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	a, err := decoder.Decode(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Semgrep Errors: %d", len(a.(*SemgrepScanReport).Errors))
}

