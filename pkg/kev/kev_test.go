package kev

import (
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"testing"
)

func TestVulnerabilities(t *testing.T) {
	r := artifact.GrypeScanReport{Matches: []models.Match{
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "B"}}},
		{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "C"}}},
	}}
	br := artifact.KEVCatalog{Vulnerabilities: []artifact.KEVCatalogVulnerability{
		{CveID: "A"},
		{CveID: "C"},
	}}

	matchedVulnerabilities := Vulnerabilities(r, br)

	if len(matchedVulnerabilities) != 2 {
		t.Error(matchedVulnerabilities)
		t.Fatal("Matching algo failed")
	}

	t.Log(VulnerabilitiesStr("2022.11.08", matchedVulnerabilities))

	t.Run("test-no-vulnerabilities", func(t *testing.T) {

		br := artifact.KEVCatalog{Vulnerabilities: []artifact.KEVCatalogVulnerability{
			{CveID: "D"},
			{CveID: "F"},
		}}

		matchedVulnerabilities := Vulnerabilities(r, br)
		if len(matchedVulnerabilities) != 0 {
			t.Fatal("False positives found")
		}

		t.Log(VulnerabilitiesStr("2022.11.08", matchedVulnerabilities))
	})

}
