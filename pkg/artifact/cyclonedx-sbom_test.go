package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"gopkg.in/yaml.v3"
)

func TestCheckCyclonedxSBOM(t *testing.T) {
	f, _ := os.Open("../../test/cyclonedx-syft-sbom.json") 
	decoder := NewCyclonedxSbomReportDecoder()

	if _, err := io.Copy(decoder, f); err != nil {
		t.Fatal(err)
	}
	goodReport, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}

	testTable := []struct {
		label   string
		input   *CyclonedxSbomReport
		wantErr error
	}{
		{label: "success", input: goodReport.(*CyclonedxSbomReport), wantErr: nil},
		{label: "nil-report", input: nil, wantErr: ErrNilObject},
		{label: "empty-report", input: &CyclonedxSbomReport{}, wantErr: ErrFailedCheck},
	}

	for i, v := range testTable {
		t.Run(fmt.Sprintf("test-%d-%s", i, v.label), func(t *testing.T) {
			if err := checkCyclonedxSBOM(v.input); !errors.Is(err, v.wantErr) {
				t.Fatalf("want: %v, got: %v", v.wantErr, err)
			}
		})
	}
}

func TestCyclonedxConfig(t *testing.T) {
	config := &CyclonedxConfig{
		AllowList: []CyclonedxListItem{{
			Id:     "cve123",
			Reason: "some reason",
		}},
		DenyList: []CyclonedxListItem{{
			Id:     "cve123",
			Reason: "some deny reason",
		}},
	}

	buf := new(bytes.Buffer)

	yaml.NewEncoder(buf).Encode(config)

	t.Logf("\n%s", buf)
}

func TestCyclonedxAllowList(t *testing.T) {
	report := &CyclonedxSbomReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Medium", "CVE-2023-3")

	config := NewConfig()
	config.Cyclonedx.Critical = 0
	config.Cyclonedx.AllowList = []CyclonedxListItem{{Id: "CVE-2023-1", Reason: "Because..."}}

	t.Log(config.Grype.AllowList)

	t.Log(report)

	if err := ValidateCyclonedx(*config.Cyclonedx, *report); err != nil {
		t.Fatal(err)
	}
}

func TestCyclonedxDenyList(t *testing.T) {
	report := &CyclonedxSbomReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")

	config := NewConfig()
	config.Cyclonedx.Critical = 0
	config.Cyclonedx.DenyList = []CyclonedxListItem{{Id: "CVE-2023-3", Reason: "Because..."}}

	t.Log(config.Cyclonedx.DenyList)

	t.Log(report)

	if err := ValidateCyclonedx(*config.Cyclonedx, *report); err == nil {
		t.Fatal("Expected Validation error for CVE-2023-3")
	}
}

func TestCyclonedxSbomShim(t *testing.T) {
	report := &CyclonedxSbomReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")

	config := NewConfig()
	config.Cyclonedx.Critical = 0
	config.Cyclonedx.DenyList = []CyclonedxListItem{{Id: "CVE-2023-3", Reason: "Because..."}}

	t.Log(config.Cyclonedx.DenyList)

	t.Log(report)

	report = report.ShimComponentsAsVulnerabilities()
	if strings.Contains(report.vulnsString(), "Total: 6") == false {
		t.Fatal("Expected 'Total: 6' in ", report.vulnsString())
	}
}

func addCyclonedxVul(r *CyclonedxSbomReport, severity string, id string) {
	vuln := cdx.Vulnerability{
		ID:      id,
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
		Affects: &[]cdx.Affects{{Ref: id + "-ref"}},
	}
	addCyclonedxComponent(r, id)
	*r.Vulnerabilities = append(*r.Vulnerabilities, vuln)
}

func addCyclonedxComponent(r *CyclonedxSbomReport, id string) {
	comp := cdx.Component{BOMRef: id + "-ref", Name: id + "-name", Version: id + "-version", Type: cdx.ComponentTypeLibrary}
	*r.Components = append(*r.Components, comp)
}
