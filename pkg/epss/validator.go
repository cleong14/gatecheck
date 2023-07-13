package epss

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

var ErrService = errors.New("service error")

type EPSSWriter interface {
	WriteEPSS([]CVE) error
}
type matchWithEPSS struct {
	match  models.Match
	cvePtr *CVE
}
type Validator struct {
	epssWriter EPSSWriter
}

func NewValidator(epssWriter EPSSWriter) *Validator {
	return &Validator{epssWriter: epssWriter}
}

func (v *Validator) Validate(report *grype.ScanReport, configReader io.Reader) error {
	configBytes, err := io.ReadAll(configReader)

	config, err := gcv.ConfigByField[grype.Config](bytes.NewReader(configBytes), grype.ConfigFieldName)
	if err != nil {
		return err
	}
	// EPSSDenyThreshold Default value is 0 so replace that value with 1 since 1 encompasses all scores
	// This is to still allow for the possibility of denying scores over a threshold
	if config.EPSSDenyThreshold == 0 {
		config.EPSSDenyThreshold = 1
	}

	if len(report.Matches) == 0 {
		return nil
	}

	reportVulnerabilities := make(map[string]matchWithEPSS, len(report.Matches))

	cves := make([]CVE, 0, len(report.Matches))

	for i, match := range report.Matches {

		cves = append(cves, CVE{ID: match.Vulnerability.ID, Severity: match.Vulnerability.Severity, Link: match.Vulnerability.DataSource})
		reportVulnerabilities[match.Vulnerability.ID] = matchWithEPSS{match: match, cvePtr: &cves[i]}
	}

	if err := v.epssWriter.WriteEPSS(cves); err != nil {
		return fmt.Errorf("%w: %v", ErrService, err)
	}
	allowed := []string{}
	report.RemoveMatches(func(m models.Match) bool {
		e, ok := reportVulnerabilities[m.Vulnerability.ID]
		if ok && e.cvePtr.Probability <= config.EPSSAllowThreshold {
			allowed = append(allowed, m.Vulnerability.ID)
			delete(reportVulnerabilities, m.Vulnerability.ID)
			return true
		}
		return false
	})
	removedList := ""
	if len(allowed) != 0 {
		removedList = strings.Join(allowed, ", ")
	}
	log.Infof("EPSS approved vulnerabilities[%d]: %s", len(allowed), removedList)

	var denied []string
	for _, vul := range reportVulnerabilities {
		if vul.cvePtr.Probability >= config.EPSSDenyThreshold {
			denied = append(denied, vul.cvePtr.ID)
		}
	}

	deniedList := ""
	if len(denied) != 0 {
		deniedList = strings.Join(denied, ", ")
	}
	log.Infof("EPSS denied vulnerabilities[%d]: %s", len(denied), deniedList)

	if len(denied) > 0 {
		return fmt.Errorf("%w: %d vulnerabilities have EPSS scores over deny threshold %.5f",
			gcv.ErrValidation, len(denied), config.EPSSDenyThreshold)
	}
	return nil
}
