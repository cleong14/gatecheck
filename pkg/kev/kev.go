package kev

import (
	"fmt"
	"time"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

/*
Cyber Infrastructure and Security Agency (CISA) Known Exploited Vulnerabilities

CISA maintains the authoritative source of vulnerabilities that have been exploited in the
wild: the Known Exploited Vulnerability (KEV) catalog. CISA strongly recommends all organizations review and monitor
the KEV catalog and prioritize remediation of the listed vulnerabilities to reduce the
likelihood of compromise by known threat actors.
*/

const FileTypeJSON = "CISA KEV Catalog [JSON]"
const CVERecordURL = "https://www.cve.org/CVERecord?id=%s"

type Catalog struct {
	Title           string          `json:"title"`
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    time.Time       `json:"dateReleased"`
	Count           int             `json:"count"`
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

func NewJSONDecoder() *gce.JSONWriterDecoder[Catalog] {
	return gce.NewJSONWriterDecoder[Catalog](FileTypeJSON, check)
}

func check(catalog *Catalog) error {
	if catalog == nil {
		return gce.ErrFailedCheck
	}
	if catalog.Title == "" {
		return fmt.Errorf("%w: Missing Title", gce.ErrFailedCheck)
	}
	if catalog.CatalogVersion == "" {
		return fmt.Errorf("%w: Missing Version", gce.ErrFailedCheck)
	}
	if len(catalog.Vulnerabilities) < 1 {
		return fmt.Errorf("%w: Missing Vulnerabilities", gce.ErrFailedCheck)
	}
	return nil
}
