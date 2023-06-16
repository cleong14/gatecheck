package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestCheckSemgrep(t *testing.T) {
	f, _ := os.Open("../../test/semgrep-sast-report.json")

	decoder := NewSemgrepReportDecoder()

	if _, err := io.Copy(decoder, f); err != nil {
		t.Fatal(err)
	}
	goodReport, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}

	testTable := []struct {
		label   string
		input   *SemgrepScanReport
		wantErr error
	}{
		{label: "success", input: goodReport.(*SemgrepScanReport), wantErr: nil},
		{label: "nil-report", input: nil, wantErr: ErrNilObject},
		{label: "empty-report", input: &SemgrepScanReport{}, wantErr: ErrFailedCheck},
	}

	for i, v := range testTable {
		t.Run(fmt.Sprintf("test-%d-%s", i, v.label), func(t *testing.T) {
			if err := checkSemgrep(v.input); !errors.Is(err, v.wantErr) {
				t.Fatalf("want: %v, got: %v", v.wantErr, err)
			}
		})
	}
}

func TestSemgrepAutoDecoder(t *testing.T) {
	f, _ := os.Open("../../test/semgrep-sast-report.json")
	decoder := new(AsyncDecoder).WithDecoders(StandardDecoders()...)
	decoder.ReadFrom(f)

	report, err := decoder.Decode(context.Background())

	if err != nil {
		t.Fatal(err)
	}

	semgrepReport, ok := report.(*SemgrepScanReport)
	if !ok {
		t.Fatalf("Type assertion failed, Type -> %T", report)
	}
	if semgrepReport.Version == nil {
		t.Fatal("want: string value, got: nil")
	}

	if gotType := GatecheckTypeID(report); gotType != TypeSemgrepScanReport {
		t.Fatalf("want %v, got %v", TypeSemgrepScanReport, gotType)
	}

}

func TestConflict(t *testing.T) {
	f, _ := os.Open("../../test/semgrep-sast-report.json")

	decoder := new(AsyncDecoder).WithDecoders(new(ConfigWriter))
	decoder.ReadFrom(f)
	config, err := decoder.Decode(context.Background())
	if err == nil {
		t.Logf("%+v", config)
		t.Fatal("Expected an error for file type collision")
	}
}
