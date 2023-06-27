package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcs "github.com/gatecheckdev/gatecheck/pkg/strings"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"github.com/zricethezav/gitleaks/v8/report"
)

const ReportType = "Gitleaks Scan Report"
const ConfigType = "Gitleaks Config"
const FieldName = "gitleaks"

type Finding report.Finding

type ScanReport []Finding

func (r ScanReport) String() string {
	table := new(gcs.Table).WithHeader("Rule", "File", "Secret", "Commit")
	for _, finding := range r {
		secret := gcs.ClipLeft(finding.Secret, 50)
		table = table.WithRow(finding.RuleID, finding.File, secret, finding.Commit)
	}
	return table.String()
}

func NewGitleaksReportDecoder() *gitleaksReportDecoder {
	return new(gitleaksReportDecoder)
}

// Gitleaks reports are just an array of findings. No findings is '[]' literally
type gitleaksReportDecoder struct {
	bytes.Buffer
}

func (d *gitleaksReportDecoder) Decode() (any, error) {
	if d == nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrEncoding, "decoder buffer is nil")
	}

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

func (d *gitleaksReportDecoder) FileType() string {
	return ReportType
}

type OuterConfig struct {
	Gitleaks *Config `json:"gitleaks,omitempty" yaml:"gitleaks,omitempty"`
}

type Config struct {
	Required       bool `yaml:"required" json:"required"`
	SecretsAllowed bool `yaml:"secretsAllowed" json:"secretsAllowed"`
}

func NewConfigDecoder() *gce.YAMLWriterDecoder[OuterConfig] {
	return gce.NewYAMLWriterDecoder[OuterConfig](ConfigType, checkConfig)
}

func checkConfig(config *OuterConfig) error {
	if config == nil {
		return fmt.Errorf("%w: no config file", gce.ErrFailedCheck)
	}
	if config.Gitleaks == nil {
		return fmt.Errorf("%w: No gitleaks configuration found", gce.ErrFailedCheck)
	}
	return nil
}

func validateFunc(scanReport ScanReport, outer OuterConfig) error {
	config := outer.Gitleaks
	if config == nil {
		return fmt.Errorf("%w: No gitleaks configuration provided", gcv.ErrValidation)
	}

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
