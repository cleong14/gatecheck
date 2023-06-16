package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
)


func TestGitleaksDecoder(t *testing.T) {
	f, _ := os.Open("../../test/gitleaks-report.json") 
	goodDecoder := NewGitleaksReportDecoder()
	if _, err := io.Copy(goodDecoder, f); err != nil {
		t.Fatal(err)
	}
	noFindingsDecoder := NewGitleaksReportDecoder()
	io.WriteString(noFindingsDecoder, "[]")

	encodingErrorDecoder := NewGitleaksReportDecoder()
	io.WriteString(encodingErrorDecoder, "{{{{{")

	noRuleIDDecoder := NewGitleaksReportDecoder()
	io.WriteString(noRuleIDDecoder, "[{\"RuleID\":\"\"}]")
	
	testTable := []struct {
		label   string
		input   *gitleaksReportDecoder
		wantErr error
	}{
		{label: "success", input: goodDecoder, wantErr: nil},
		{label: "no-findings", input: noFindingsDecoder, wantErr: nil},
		{label: "encoding-error", input: encodingErrorDecoder, wantErr: ErrEncoding},
		{label: "nil-buf-error", input: nil, wantErr: ErrDecoders},
		{label: "no-ruleid-error", input: noRuleIDDecoder, wantErr: ErrFailedCheck},
	}

	for i, v := range testTable {
		t.Run(fmt.Sprintf("test-%d-%s", i, v.label), func(t *testing.T) {
			if _, err := v.input.Decode(); !errors.Is(err, v.wantErr) {
				t.Fatalf("want: %v, got: %v", v.wantErr, err)
			}
		})
	}
}
