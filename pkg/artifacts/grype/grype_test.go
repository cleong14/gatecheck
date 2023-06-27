package grype

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigDecoder(t *testing.T) {
	config := Config{Required: true, Critical: 1, High: 10}
	decoder := NewConfigDecoder()
	_ = yaml.NewEncoder(decoder).Encode(map[string]any{ConfigFieldName: config})
	c, err := decoder.Decode()
	if err != nil {
		t.Fatal(err)
	}
	decodedConfig, ok := c.(Config)
	if !ok {
		t.Fatalf("got: %T", c)
	}

	if decodedConfig.Required != config.Required {
		t.Fatalf("want: required == true")
	}
	if decodedConfig.Critical != config.Critical {
		t.Fatalf("want: %d got: %d", config.Critical, decodedConfig.Critical)
	}
	if decodedConfig.High != 10 {
		t.Fatalf("want: %d got: %d", config.High, decodedConfig.High)
	}
	t.Logf("%+v\n",decodedConfig)
}

// func TestConfigDecoder(t *testing.T) {
// 	config := &OuterConfig{Grype: &ConfigOld{Required: true, Critical: 1, High: 1}}
//
// 	buf := new(bytes.Buffer)
// 	_ = yaml.NewEncoder(buf).Encode(config)
//
// 	decoder := NewConfigDecoder_old()
// 	_, _ = decoder.ReadFrom(buf)
// 	c, err := decoder.Decode()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	decodedConfig, ok := c.(*OuterConfig)
// 	if !ok {
// 		t.Fatalf("want: *OuterConfig, got: %T", c)
// 	}
// 	if decodedConfig.Grype.Critical != 1 {
// 		t.Fatalf("want: grype config == 1, got: %d", decodedConfig.Grype.Critical)
// 	}
// 	t.Logf("%+v", *decodedConfig.Grype)
// }
//
// func TestAnonConfigDecoder(t *testing.T) {
// 	anonConfig := struct {
// 		Grype   *ConfigOld     `yaml:"grype,omitempty"`
// 		Semgrep *MockConfig `yaml:"mock,omitempty"`
// 	}{Grype: &ConfigOld{Required: true, Critical: 1, High: 1}}
//
// 	buf := new(bytes.Buffer)
// 	_ = yaml.NewEncoder(buf).Encode(anonConfig)
//
// 	decoder := NewConfigDecoder_old()
// 	_, _ = decoder.ReadFrom(buf)
// 	c, err := decoder.Decode()
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	decodedConfig, ok := c.(*OuterConfig)
// 	if !ok {
// 		t.Fatalf("want: *OuterConfig, got: %T", c)
// 	}
// 	if decodedConfig.Grype.Critical != 1 {
// 		t.Fatalf("want: grype config == 1, got: %d", decodedConfig.Grype.Critical)
// 	}
// 	t.Logf("%+v", *decodedConfig.Grype)
// }
//
// func TestAsyncDecoder_Grype(t *testing.T) {
// 	grypeBytes := MustReadFile("../../../test/grype-report.json", t.Fatal)
//
// 	decoder := new(gce.AsyncDecoder).WithDecoders(NewReportDecoder())
//
// 	_, err := decoder.ReadFrom(bytes.NewReader(grypeBytes))
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	a, err := decoder.Decode(context.Background())
// 	if err != nil {
// 		t.Fatal(err)
// 	}
//
// 	t.Logf("%+v", a.(*ScanReport).Descriptor)
// 	t.Log(decoder.FileType())
// }
//
// func TestCheckConfig(t *testing.T) {
// 	if err := checkConfig(nil); !errors.Is(err, gce.ErrFailedCheck) {
// 		t.Fatal("want: failed check error got:", err)
// 	}
// 	if err := checkConfig(&OuterConfig{Grype: nil}); !errors.Is(err, gce.ErrFailedCheck) {
// 		t.Fatal("want: failed check error got:", err)
// 	}
// 	config := ConfigOld{Critical: 0, High: 0}
// 	if err := checkConfig(&OuterConfig{Grype: &config}); err != nil {
// 		t.Fatalf("want: nil got: %v",err)
// 	}
// }

func MustReadFile(filename string, fatalFunc func(args ...any)) []byte {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		fatalFunc(err)
	}
	return fileBytes
}

type MockConfig struct {
	High int `yaml:"high"`
	Low  int `yaml:"low"`
}
