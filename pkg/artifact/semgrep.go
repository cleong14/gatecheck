package artifact

import (
	"errors"
	"fmt"
	semgrep "github.com/BacchusJackson/go-semgrep"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"strings"
)

var SemgrepFailedValidation = errors.New("semgrep failed validation")

// SemgrepScanReport is a data model for a Semgrep Output scan produced by `semgrep scan --json`
type SemgrepScanReport semgrep.SemgrepOutputV1Jsonschema

func (r SemgrepScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Path", "Line", "Level", "link", "CWE Message")

	for _, item := range r.Results {
		line := fmt.Sprintf("%d", item.Start.Line)
		// Attempt type assertion on metadata since it's an interface{}
		metadata, ok := item.Extra.Metadata.(map[string]interface{})
		if ok != true {
			table = table.WithRow(gcStrings.ClipLeft(item.Path, 30), line, item.Extra.Severity, "", "")
			continue
		}

		link := fmt.Sprintf("%v", metadata["shortlink"])
		cwe := fmt.Sprintf("%v", metadata["cwe"])
		path := gcStrings.ClipRight(item.Path, 30)
		table = table.WithRow(path, line, item.Extra.Severity, cwe, link)
	}

	return table.String()
}

func NewSemgrepReportDecoder() *JSONWriterDecoder[SemgrepScanReport] {
	return NewJSONWriterDecoder[SemgrepScanReport](checkSemgrep)
}

func checkSemgrep(report *SemgrepScanReport) error {
	if report == nil {
		return ErrNilObject
	}
	if report.Results == nil {
		return fmt.Errorf("%w: Required field 'Results' is nil", ErrFailedCheck)
	}
	if report.Errors == nil {
		return fmt.Errorf("%w: Required field 'Errors' is nil", ErrFailedCheck)
	}
	if report.Paths.Scanned == nil {
		return fmt.Errorf("%w: Required field 'Scanned' is nil", ErrFailedCheck)
	}
	return nil
}

type SemgrepConfig struct {
	Required bool `yaml:"required" json:"required"`
	Info     int  `yaml:"info" json:"info"`
	Warning  int  `yaml:"warning" json:"warning"`
	Error    int  `yaml:"error" json:"error"`
}

func ValidateSemgrep(config SemgrepConfig, scanReport SemgrepScanReport) error {
	allowed := map[string]int{"INFO": config.Info, "WARNING": config.Warning, "ERROR": config.Error}
	found := map[string]int{"INFO": 0, "WARNING": 0, "ERROR": 0}

	for _, result := range scanReport.Results {
		found[result.Extra.Severity] += 1
	}

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}
	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", SemgrepFailedValidation, strings.Join(errStrings, ", "))

}
