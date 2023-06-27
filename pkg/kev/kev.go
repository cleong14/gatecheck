package kev

import (
	"fmt"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

/*
Cyber Infrastructure and Security Agency (CISA) Known Exploited Vulnerabilities

CISA maintains the authoritative source of vulnerabilities that have been exploited in the
wild: the Known Exploited Vulnerability (KEV) catalog. CISA strongly recommends all organizations review and monitor
the KEV catalog and prioritize remediation of the listed vulnerabilities to reduce the
likelihood of compromise by known threat actors.
*/

type Catalog struct {
	Title           string                    `json:"title"`
	CatalogVersion  string                    `json:"catalogVersion"`
	DateReleased    time.Time                 `json:"dateReleased"`
	Count           int                       `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	DateAdded         string `json:"dateAdded"`
	ShortDescription  string `json:"shortDescription"`
	RequiredAction    string `json:"requiredAction"`
	DueDate           string `json:"dueDate"`
	Notes             string `json:"notes"`
}

func NewDecoder() *artifact.JSONWriterDecoder[Catalog] {
	return artifact.NewJSONWriterDecoder[Catalog](check)
}

func check(catalog *Catalog) error {
	if catalog == nil {
		return artifact.ErrNilObject
	}
	if catalog.Title == "" {
		return fmt.Errorf("%w: Missing Title", artifact.ErrFailedCheck)
	}
	if catalog.CatalogVersion == "" {
		return fmt.Errorf("%w: Missing Version", artifact.ErrFailedCheck)
	}
	if len(catalog.Vulnerabilities) < 1 {
		return fmt.Errorf("%w: Missing Vulnerabilities", artifact.ErrFailedCheck)
	}
	return nil
}

func Vulnerabilities(report artifact.GrypeScanReport, catalog artifact.KEVCatalog) []artifact.KEVCatalogVulnerability {
	matchedVulnerabilities := make([]artifact.KEVCatalogVulnerability, 0)

	for _, reportedVulnerability := range report.Matches {
		for _, badCVE := range catalog.Vulnerabilities {
			if reportedVulnerability.Vulnerability.ID == badCVE.CveID {
				matchedVulnerabilities = append(matchedVulnerabilities, badCVE)
			}
		}
	}

	return matchedVulnerabilities
}

func VulnerabilitiesStr(catVersion string, v []artifact.KEVCatalogVulnerability) string {
	var sb strings.Builder
	sb.WriteString("CISA KEV Catalog Vulnerabilities Report\n")
	sb.WriteString(fmt.Sprintf("Catalog Version: %s\n", catVersion))

	if len(v) == 0 {
		sb.WriteString("0 Vulnerabilities Matched to Catalog\n")
		return sb.String()
	}

	table := new(gcStrings.Table).WithHeader("CVE ID", "Date Added", "CVE.org Link", "Vulnerability Name")

	for _, value := range v {
		link := fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", value.CveID)
		table = table.WithRow(value.CveID, value.DateAdded, link, value.VulnerabilityName)

	}

	sb.WriteString(table.String())
	return sb.String()
}
