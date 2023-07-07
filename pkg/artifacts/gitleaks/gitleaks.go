package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"github.com/zricethezav/gitleaks/v8/report"
)

const ReportType = "Gitleaks Scan Report"
const ConfigType = "Gitleaks Config"
const ConfigFieldName = "gitleaks"

type Finding report.Finding

type ScanReport []Finding

func (r ScanReport) String() string {
	table := format.NewTable()
	table.AppendRow("Rule", "File", "secret", "Commit")
	for _, finding := range r {
		secret := format.Summarize(finding.Secret, 50, format.ClipLeft)
		table.AppendRow(finding.RuleID, finding.File, secret, finding.Commit)
	}
	return format.NewTableWriter(table).String()
}

type Config struct {
	Required       bool `yaml:"required" json:"required"`
	SecretsAllowed bool `yaml:"secretsAllowed" json:"secretsAllowed"`
}

func NewValidator() *gcv.Validator[ScanReport, Config] {
	return gcv.NewValidator[ScanReport, Config](ConfigFieldName, NewReportDecoder(), validateFunc)
}

func NewReportDecoder() *ReportDecoder {
	return new(ReportDecoder)
}

// Gitleaks reports are just an array of findings. No findings is '[]' literally
type ReportDecoder struct {
	bytes.Buffer
}

func (d *ReportDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	return d.Decode()
}

func (d *ReportDecoder) Decode() (any, error) {
	// Edge Case: report with no findings
	if d.String() == "[]" {
		return &ScanReport{}, nil
	}

	obj := ScanReport{}
	err := json.NewDecoder(d).Decode(&obj)

	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrEncoding, err)
	}

	if obj[0].RuleID == "" {
		return nil, fmt.Errorf("%w: rule id is missing", gce.ErrFailedCheck)
	}

	return &obj, nil
}

func (d *ReportDecoder) FileType() string {
	return ReportType
}

func validateFunc(scanReport ScanReport, config Config) error {
	if len(scanReport) == 0 {
		return nil
	}
	msg := fmt.Sprintf("Gitleaks: %d secrets detected", len(scanReport))
	log.Info(msg)
	if config.SecretsAllowed {
		return nil
	}
	return fmt.Errorf("%w: %s", gcv.ErrValidation, msg)
}
