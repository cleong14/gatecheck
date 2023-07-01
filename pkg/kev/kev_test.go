package kev

import (
	"bytes"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
)

func TestVulnerabilities(t *testing.T) {
	r := &grype.ScanReport{Matches: []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "B"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "C"}}},
	}}
	catalog := Catalog{Vulnerabilities: []Vulnerability{
		{CveID: "A"},
		{CveID: "C"},
	}}

	service := new(Service)
	service.catalog = catalog

	service = service.WithReport(r)

	if len(service.MatchedVulnerabilities()) != 2 {
		t.Fatal("want: 2 got:", service.MatchedVulnerabilities())
	}

	buf := new(bytes.Buffer)

	_, _ = service.WriteTo(buf)
	t.Log(buf.String())

	t.Run("test-no-vulnerabilities", func(t *testing.T) {

		catalog := Catalog{Vulnerabilities: []Vulnerability{
			{CveID: "D"},
			{CveID: "F"},
		}}

		service := new(Service)
		service.catalog = catalog

		service = service.WithReport(r)

		if len(service.MatchedVulnerabilities()) != 0 {
			t.Fatal("False positives found")
		}
	})

}
