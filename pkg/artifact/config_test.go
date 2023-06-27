package artifact

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfig_IsRequired(t *testing.T) {

	config := NewConfig()
	config.Grype.Required = true

	if config.Required()[0] != TypeGrypeScanReport {
		t.Fatalf("want: %s, got: %s", TypeGrypeScanReport, config.Required()[0])
	}
	if _, ok := config.Declared()[TypeGrypeScanReport].(*GrypeConfig); !ok {
		t.Fatalf("want: %s, got: %T", "*GrypeScanReport", config.Declared()[TypeGrypeScanReport])
	}
}

func TestConfigReadWriter_Decode(t *testing.T) {

	testTable := []struct {
		label   string
		input   *ConfigWriter
		wantErr error
	}{
		{label: "success", wantErr: nil},
		{label: "encoding-error", wantErr: ErrEncoding},
		{label: "missing-version-error", wantErr: ErrFailedCheck},
	}
	f, _ := os.Open("../../test/gatecheck.yaml")
	testTable[0].input = new(ConfigWriter)
	_, _ = testTable[0].input.ReadFrom(f)

	testTable[1].input = new(ConfigWriter)
	_, _ = testTable[1].input.ReadFrom(bytes.NewBufferString("{{{{{"))

	testTable[2].input = new(ConfigWriter)
	_ = yaml.NewEncoder(testTable[2].input).Encode(&Config{Version: ""})

	for i, v := range testTable {
		t.Run(fmt.Sprintf("test-%d-%s", i, v.label), func(t *testing.T) {
			if _, err := v.input.Decode(); !errors.Is(err, v.wantErr) {
				t.Fatalf("want: %v, got: %v", v.wantErr, err)
			}
		})
	}
}

func TestConfigReadWriter_Encode(t *testing.T) {

	testTable := []struct {
		label     string
		encodeObj *Config
		wantErr   error
	}{
		{label: "success", encodeObj: NewConfig(), wantErr: nil},
		{label: "nil-object", encodeObj: nil, wantErr: ErrNilObject},
		{label: "missing-version-error", encodeObj: &Config{Version: ""}, wantErr: ErrFailedCheck},
	}

	for i, v := range testTable {
		t.Run(fmt.Sprintf("test-%d-%s", i, v.label), func(t *testing.T) {
			if _, err := NewConfigReader(v.encodeObj); !errors.Is(err, v.wantErr) {

				t.Fatalf("want: %v, got: %v", v.wantErr, err)
			}
		})
	}
}
