package kev

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcs "github.com/gatecheckdev/gatecheck/pkg/strings"
)

var ErrAPI = errors.New("API Query failed")

type Service struct {
	catalog               Catalog
	report                *grype.ScanReport
	matchedVulnerabilites []Vulnerability
}

func NewServiceFromFile(r io.Reader) (*Service, error) {
	decoder := gce.NewAsyncDecoder(NewCSVDecoder(), NewJSONDecoder())

	service := new(Service)
	obj, err := decoder.DecodeFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	service.catalog = *obj.(*Catalog)
	return service, nil
}

func NewServiceFromAPI(url string, client *http.Client) (*Service, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	res, err := client.Do(req)
	if err != nil {
		return nil, errors.Join(ErrAPI, err)
	}
	return NewServiceFromFile(res.Body)
}

func (s *Service) WithReport(report *grype.ScanReport) *Service {
	s.report = report
	s.innerJoin()
	return s
}

func (s *Service) LoadFrom(reportReader io.Reader) error {
	o, err := grype.NewReportDecoder().DecodeFrom(reportReader)
	if err != nil {
		return fmt.Errorf("%w: %v", gce.ErrEncoding, err)
	}
	s = s.WithReport(o.(*grype.ScanReport))

	return nil
}

func (s *Service) innerJoin() {
	s.matchedVulnerabilites = make([]Vulnerability, 0)
	for _, reportedVulnerability := range s.report.Matches {
		for _, badCVE := range s.catalog.Vulnerabilities {
			if strings.ToLower(reportedVulnerability.Vulnerability.ID) == strings.ToLower(badCVE.CveID) {
				s.matchedVulnerabilites = append(s.matchedVulnerabilites, badCVE)
			}
		}
	}
}

func (s *Service) MatchedVulnerabilities() []Vulnerability {
	return s.matchedVulnerabilites
}

func (s *Service) Catalog() Catalog {
	return s.catalog
}

func (s *Service) WriteTo(w io.Writer) (int64, error) {
	var sb strings.Builder
	sb.WriteString("CISA KEV Catalog Vulnerabilities Report\n")
	sb.WriteString(fmt.Sprintf("Catalog Version: %s\n", s.catalog.CatalogVersion))
	if len(s.matchedVulnerabilites) == 0 {
		sb.WriteString("0 Vulnerabilities Matched to Catalog\n")
		return strings.NewReader(sb.String()).WriteTo(w)
	}

	table := new(gcs.Table).WithHeader("CVE ID", "Date Added", "CVE.org Link", "Vulnerability Name")

	for _, value := range s.matchedVulnerabilites {
		link := fmt.Sprintf(CVERecordURL, value.CveID)
		table = table.WithRow(value.CveID, value.DateAdded, link, value.VulnerabilityName)

	}

	sb.WriteString(table.String())
	return strings.NewReader(sb.String()).WriteTo(w)
}
