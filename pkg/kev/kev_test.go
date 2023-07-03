package kev

import (
	"bytes"
	"errors"
	"testing"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
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

func TestCheck(t *testing.T) {
	testTable := []struct {
		label      string
		wantErr    error
		useCatalog *Catalog
	}{
		{label: "success", wantErr: nil, useCatalog: &Catalog{Title: "some title", CatalogVersion: "v1", Vulnerabilities: []Vulnerability{{CveID: "abc1"}, {CveID: "abc2"}}}},
		{label: "nil-catalog", wantErr: gce.ErrFailedCheck, useCatalog: nil},
		{label: "no-title", wantErr: gce.ErrFailedCheck, useCatalog: &Catalog{Title: ""}},
		{label: "no-catalog-version", wantErr: gce.ErrFailedCheck, useCatalog: &Catalog{Title: "a", CatalogVersion: ""}},
		{label: "no-catalog-vulnerabilities", wantErr: gce.ErrFailedCheck, useCatalog: &Catalog{Title: "a", CatalogVersion: "a", Vulnerabilities: []Vulnerability{}}},
	}

	for _, testCase := range testTable {
		if err := check(testCase.useCatalog); !errors.Is(err, testCase.wantErr) {
			t.Fatalf("want: %v got: %v", testCase.wantErr, err)
		}
	}

}
