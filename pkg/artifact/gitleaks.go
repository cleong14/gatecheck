package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gatecheckdev/gatecheck/internal/log"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"github.com/zricethezav/gitleaks/v8/report"
)

type GitleaksFinding report.Finding

type GitleaksScanReport []GitleaksFinding

var GitleaksValidationFailed = errors.New("gitleaks validation failed")

func (r GitleaksScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Rule", "File", "Secret", "Commit")
	for _, finding := range r {
		secret := gcStrings.ClipLeft(finding.Secret, 50)
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
		return nil, fmt.Errorf("%w: %v", ErrDecoders, "decoder buffer is nil")
	}

	// Edge Case: report with no findings
	if d.String() == "[]" {
		return &GitleaksScanReport{}, nil
	}

	obj := GitleaksScanReport{}
	err := json.NewDecoder(d).Decode(&obj)

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}

	if obj[0].RuleID == "" {
		return nil, fmt.Errorf("%w: rule id is missing", ErrFailedCheck)
	}

	return &obj, nil
}

type GitleaksConfig struct {
	Required       bool `yaml:"required" json:"required"`
	SecretsAllowed bool `yaml:"secretsAllowed" json:"secretsAllowed"`
}

func ValidateGitleaksPtr(config Config, report any) error {
	if config.Gitleaks == nil {
		return fmt.Errorf("%w: No Gitleaks validation rules", ErrValidation)
	}

	scanReport, ok := report.(*GitleaksScanReport)
	if !ok {
		return fmt.Errorf("%w: %T is an invalid report type", ErrValidation, scanReport)
	}
	return ValidateGitleaks(*config.Gitleaks, *scanReport)
}

func ValidateGitleaks(config GitleaksConfig, scanReport GitleaksScanReport) error {
	if len(scanReport) == 0 {
		return nil
	}
	msg := fmt.Sprintf("Gitleaks: %d secrets detected", len(scanReport))
	log.Info(msg)
	if config.SecretsAllowed {
		return nil
	}
	return fmt.Errorf("%w: %s", GitleaksValidationFailed, msg)
}
