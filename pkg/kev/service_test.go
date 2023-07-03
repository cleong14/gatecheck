package kev

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestFetch(t *testing.T) {

	t.Run("success", func(t *testing.T) {

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			catalog := &Catalog{Title: "Mock Catalog", CatalogVersion: "Mock Version", DateReleased: time.Now(), Count: 1,
				Vulnerabilities: []Vulnerability{{CveID: "abc-123"}}}
			_ = json.NewEncoder(w).Encode(catalog)
		}))

		service, err := NewServiceFromAPI(mockServer.URL, mockServer.Client())
		if err != nil {
			t.Fatal(err)
		}

		if len(service.Catalog().Vulnerabilities) != 1 {
			t.Fatal("want: 1 got:", len(service.Catalog().Vulnerabilities))
		}

		t.Run("print-with-match", func(t *testing.T) {
			grypeReport := &grype.ScanReport{}
			grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
			}})

			service.WithReport(grypeReport)

			buf := new(bytes.Buffer)
			_, _ = service.WriteTo(buf)
			t.Log(buf.String())

		})

		t.Run("print-with-no-match", func(t *testing.T) {
			grypeReport := &grype.ScanReport{}
			grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
				VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "def-345", Severity: "Critical"},
			}})

			service.WithReport(grypeReport)

			buf := new(bytes.Buffer)
			_, _ = service.WriteTo(buf)
			t.Log(buf.String())

		})

	})

	t.Run("bad-reader", func(t *testing.T) {
		_, err := NewServiceFromFile(&badReader{})
		if !errors.Is(err, gce.ErrIO) {
			t.Fatalf("want: %v got: %v", gce.ErrIO, err)
		}
	})

	t.Run("bad-server", func(t *testing.T) {
		mockServer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
		mockServer.Close()

		_, err := NewServiceFromAPI(mockServer.URL, mockServer.Client())
		if !errors.Is(err, ErrAPI) {
			t.Fatalf("want: %v got: %v", ErrAPI, err)
		}
	})
}

func TestService_LoadFrom(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		grypeReport := &grype.ScanReport{}
		grypeReport.Descriptor.Name = "grype"
		grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
			VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
		}})
		buf := new(bytes.Buffer)
		_ = json.NewEncoder(buf).Encode(grypeReport)

		err := new(Service).LoadFrom(buf)
		if err != nil {
			t.Fatal(err)
		}

	})

	t.Run("bad-reader", func(t *testing.T) {
		err := new(Service).LoadFrom(&badReader{})
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

}
