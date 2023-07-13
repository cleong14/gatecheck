package kev

import (
	"fmt"
	"io"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

type Validator struct {
	service *Service
}

func NewValidator(service *Service) *Validator {
	return &Validator{service: service}
}

func (v *Validator) Validate(report *grype.ScanReport, configReader io.Reader) error {
	denied := v.service.WithReport(report).MatchedVulnerabilities()
	if len(denied) > 0 {
		word := "Vulnerabilities"
		if len(denied) == 1 {
			word = "Vulnerability"
		}
		return fmt.Errorf("%w: %d %s matched to KEV Catalog", gcv.ErrValidation, len(denied), word)
	}

	return nil
}
