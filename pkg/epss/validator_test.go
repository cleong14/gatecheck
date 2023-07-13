package epss

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v3"
)

func TestValidator_Validate(t *testing.T) {
	t.Run("success-pass", func(t *testing.T) {
		scoreMap := map[string]float64{"cve-1": 0.01, "cve-2": 0.02, "cve-3": 0.03, "cve-4": 0.04, "cve-5": 0.05}
		w := &mockWriter{returnErr: nil, run: func(c []CVE) {
			for i, cve := range c {
				c[i].Probability = scoreMap[cve.ID]
			}
		}}

		configBuf := new(bytes.Buffer)
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		_ = yaml.NewEncoder(configBuf).Encode(configMap)

		report := mockReport()
		err := NewValidator(w).Validate(report, configBuf)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("success-fail", func(t *testing.T) {
		scoreMap := map[string]float64{"cve-1": 0.01, "cve-2": 0.52, "cve-3": 0.03, "cve-4": 0.04, "cve-5": 0.05}
		w := &mockWriter{returnErr: nil, run: func(c []CVE) {
			for i, cve := range c {
				c[i].Probability = scoreMap[cve.ID]
			}
		}}

		configBuf := new(bytes.Buffer)
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .4, EPSSDenyThreshold: .5}}
		_ = yaml.NewEncoder(configBuf).Encode(configMap)

		report := mockReport()
		err := NewValidator(w).Validate(report, configBuf)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
		if len(report.Matches) != 1 {
			t.Fatal("An approved vulnerability should be removed from the report")
		}
	})

	t.Run("bad-config", func(t *testing.T) {
		err := NewValidator(&mockWriter{}).Validate(mockReport(), strings.NewReader("{{{"))
		if err == nil {
			t.Fatalf("want: error for bad config got: %v", err)
		}
	})

	t.Run("no-matches", func(t *testing.T) {
		configBuf := new(bytes.Buffer)
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		err := NewValidator(&mockWriter{}).Validate(&grype.ScanReport{}, configBuf)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("bad-service", func(t *testing.T) {
		configBuf := new(bytes.Buffer)
		configMap := map[string]any{grype.ConfigFieldName: grype.Config{EPSSAllowThreshold: .5}}
		_ = yaml.NewEncoder(configBuf).Encode(configMap)
		err := NewValidator(&mockWriter{returnErr: errors.New("")}).Validate(mockReport(), configBuf)

		if !errors.Is(err, ErrService) {
			t.Fatalf("want: %v got: %v", ErrService, err)
		}
	})

}

func mockReport() *grype.ScanReport {
	report := &grype.ScanReport{}
	report.Matches = []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "High"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "Low"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "Medium"}}},
	}
	return report
}

type mockWriter struct {
	returnErr error
	run       func([]CVE)
}

func (w *mockWriter) WriteEPSS(cves []CVE) error {
	if w.run != nil {
		w.run(cves)
	}
	return w.returnErr
}
