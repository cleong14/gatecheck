package grype

import (
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcs "github.com/gatecheckdev/gatecheck/pkg/strings"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const ReportType = "Anchore Grype Scan Report"
const ConfigType = "Anchore Grype Config"
const ConfigFieldName = "grype"

type ScanReport models.Document

func (r ScanReport) String() string {
	table := new(gcs.Table).WithHeader("Severity", "Package", "Version", "Link")

	for _, item := range r.Matches {
		table = table.WithRow(item.Vulnerability.Severity,
			item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource)
	}

	// Sort the rows by Severity then Package
	severitiesOrder := gcs.StrOrder{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
	table = table.SortBy([]gcs.SortBy{
		{Name: "Severity", Mode: gcs.AscCustom, Order: severitiesOrder},
		{Name: "Package", Mode: gcs.Asc},
	}).Sort()

	return table.String()
}

type Config struct {
	AllowList  []ListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList   []ListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	Required   bool       `yaml:"required" json:"required"`
	Critical   int        `yaml:"critical"   json:"critical"`
	High       int        `yaml:"high"       json:"high"`
	Medium     int        `yaml:"medium"     json:"medium"`
	Low        int        `yaml:"low"        json:"low"`
	Negligible int        `yaml:"negligible" json:"negligible"`
	Unknown    int        `yaml:"unknown"    json:"unknown"`
}

type ConfigOld struct {
	Grype *struct {
		AllowList  []ListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
		DenyList   []ListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
		Required   bool       `yaml:"required" json:"required"`
		Critical   int        `yaml:"critical"   json:"critical"`
		High       int        `yaml:"high"       json:"high"`
		Medium     int        `yaml:"medium"     json:"medium"`
		Low        int        `yaml:"low"        json:"low"`
		Negligible int        `yaml:"negligible" json:"negligible"`
		Unknown    int        `yaml:"unknown"    json:"unknown"`
	} `json:"grype,omitempty" yaml:"grype,omitempty"`
}

type ListItem struct {
	Id     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

func NewReportDecoder() *gce.JSONWriterDecoder[ScanReport] {
	return gce.NewJSONWriterDecoder[ScanReport](ReportType, checkReport)
}

func NewConfigDecoder_old() *gce.YAMLWriterDecoder[ConfigOld] {
	return gce.NewYAMLWriterDecoder[ConfigOld](ConfigType, checkConfig)
}

func NewConfigDecoder() *gce.MapDecoder[Config] {
	return gce.NewMapDecoder[Config](ConfigType, ConfigFieldName)
}

func checkConfig(config *ConfigOld) error {
	if config == nil {
		return gce.ErrFailedCheck
	}
	if config.Grype == nil {
		return gce.ErrFailedCheck
	}
	return nil
}

func checkReport(report *ScanReport) error {
	if report == nil {
		return gce.ErrFailedCheck
	}
	if report.Descriptor.Name != "grype" {
		return fmt.Errorf("%w: Missing Descriptor name", gce.ErrFailedCheck)
	}
	return nil
}

func NewValidator() *gcv.Validator[ScanReport, ConfigOld] {
	return gcv.NewValidator[ScanReport, ConfigOld](validateFunc).WithDecoders(NewReportDecoder(), NewConfigDecoder_old())
}

func validateFunc(scanReport ScanReport, c ConfigOld) error {
	config := c.Grype
	if config == nil {
		return fmt.Errorf("%w: No grype configuration provided", gcv.ErrValidation)
	}
	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
	allowed := map[string]int{
		"Critical": config.Critical, "High": config.High, "Medium": config.Medium,
		"Low": config.Low, "Negligible": config.Negligible, "Unknown": config.Unknown,
	}
	foundDenied := make([]models.Match, 0)

LOOPMATCH:
	for matchIndex, match := range scanReport.Matches {

		for _, allowed := range config.AllowList {
			if strings.Compare(match.Vulnerability.ID, allowed.Id) == 0 {

				log.Infof("%s Allowed. Reason: %s", match.Vulnerability.ID, allowed.Reason)
				continue LOOPMATCH
			}
		}

		for _, denied := range config.DenyList {
			if match.Vulnerability.ID == denied.Id {
				log.Infof("%s Denied. Reason: %s", match.Vulnerability.ID, denied.Reason)
				foundDenied = append(foundDenied, scanReport.Matches[matchIndex])
			}
		}

		found[match.Vulnerability.Severity] += 1
	}
	log.Infof("Grype Findings: %v", gcs.PrettyPrintMap(found))

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}

	if len(foundDenied) != 0 {
		deniedReport := &ScanReport{Matches: foundDenied}
		errStrings = append(errStrings, fmt.Sprintf("Denied Vulnerabilities\n%s", deniedReport))
	}

	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", gcv.ErrValidation, strings.Join(errStrings, ", "))
}
