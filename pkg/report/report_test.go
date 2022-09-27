package report_test

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"os"
	"strings"
	"testing"
)

var TestGrypeReport = "../../test/grype-report.json"

func TestWriteAndReadReport(t *testing.T) {
	buf := new(bytes.Buffer)
	rep := report.NewReport("Test Gatecheck Report")

	if err := json.NewEncoder(buf).Encode(rep); err != nil {
		t.Fatal(err)
	}

	rep2 := new(report.Report)
	err := json.NewDecoder(buf).Decode(rep2)
	if err != nil {
		t.Fatal(err)
	}

	if rep2.ProjectName != "Test Gatecheck Report" {
		t.Fatal("Something went wrong")
	}

	t.Run("With Scan", func(t *testing.T) {
		scanFile, err := os.Open(TestGrypeReport)
		if err != nil {
			t.Fatal(err)
		}
		scan := new(grype.ScanReport)
		if err := json.NewDecoder(scanFile).Decode(scan); err != nil {
			t.Fatal(err)
		}

		grypeAsset := grype.NewAsset("grype-report.json").WithScan(scan)

		rep.Artifacts.Grype = *grype.NewArtifact().
			WithConfig(grype.NewConfig(-1)).
			WithAsset(grypeAsset)

		t.Log(rep)
	})

	t.Run("With Config", func(t *testing.T) {
		tempConfig := config.NewConfig("Test Project")
		tempConfig.Grype.Low = 100
		tempConfig.ProjectName = "Some project name"

		rep = rep.WithConfig(tempConfig)
		t.Log(rep)

		if strings.Contains(rep.String(), tempConfig.ProjectName) != true {
			t.Fatal("Project name not updated")
		}
	})
}

func TestReport_WithSettings(t *testing.T) {
	r := report.NewReport("Test Project Name")

	r = r.WithSettings(report.Settings{ProjectName: "New Project Name"})
	r = r.WithSettings(report.Settings{PipelineId: "ABC-12345"})
	r = r.WithSettings(report.Settings{PipelineUrl: "pipeline.com"})

	if strings.Compare(r.ProjectName, "New Project Name") != 0 {
		t.Fatal("Unexpected Project Name")
	}
	if strings.Compare(r.PipelineId, "ABC-12345") != 0 {
		t.Fatal("Unexpected Pipeline ID")
	}
	if strings.Compare(r.PipelineUrl, "pipeline.com") != 0 {
		t.Fatal("Unexpected Pipeline URL")
	}

}
