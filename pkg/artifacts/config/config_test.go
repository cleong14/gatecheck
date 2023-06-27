package config

import (
	"bytes"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"gopkg.in/yaml.v3"
)

func TestDecoder(t *testing.T) {
	tempConfig := map[string]any{"version": "1", "report": map[string]any{"required": true, "high": 0, "low": 10}}
	buf := new(bytes.Buffer)
	_ = yaml.NewEncoder(buf).Encode(tempConfig)

	subDecoders := map[FieldName]gce.WriterDecoder{"report": NewReportConfigDecoder()}
	c, err := NewDecoder().WithSubDecoders(subDecoders).DecodeFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%+v", c.(*Config))
	t.Logf("%+v", c.(*Config).Artifacts["report"].(*ReportConfigOuter).Report)
	report := c.(*Config).Artifacts["report"].(*ReportConfigOuter).Report
	if report.High != 0 {
		t.Fatal("want: 0 got:", report.High)
	}
	if report.Low != 10 {
		t.Fatal("want: 10 got:", report.Low)
	}
	if report.Required != true {
		t.Fatal("want: true, got:",report.Required)
	}
}


type ReportConfigOuter struct {
	Report *ReportConfig `yaml:"report,omitempty"`
}

type ReportConfig struct {
	Required bool `yaml:"required"`
	High     int    `yaml:"high"`
	Low      int    `yaml:"low"`
}

func NewReportConfigDecoder() *gce.YAMLWriterDecoder[ReportConfigOuter] {
	return gce.NewYAMLWriterDecoder[ReportConfigOuter]("Mock Report", func(rco *ReportConfigOuter) error { return nil })
}
