package kev

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

func TestValidator_Validate(t *testing.T) {
	catalog := &Catalog{Title: "Mock Catalog", CatalogVersion: "mockVersion",
		Vulnerabilities: []Vulnerability{{CveID: "cve-1"}, {CveID: "cve-2"}, {CveID: "cve-3"}, {CveID: "cve-4"}}}
	t.Run("success-pass", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = json.NewEncoder(buf).Encode(catalog)
		service, _ := NewServiceFromFile(buf)

		err := NewValidator(service).Validate(&grype.ScanReport{}, nil)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("success-fail", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_ = json.NewEncoder(buf).Encode(catalog)
		service, _ := NewServiceFromFile(buf)

		report := &grype.ScanReport{}
		report.Matches = []models.Match{
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		}

		err := NewValidator(service).Validate(report, nil)
		t.Log(err)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
		report.Matches = []models.Match{
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
			{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Critical"}}},
		}

		err = NewValidator(service).Validate(report, nil)
		t.Log(err)
		if !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}

	})
}
