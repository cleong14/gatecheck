package artifact

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version   string           `yaml:"version" json:"version"`
	Cyclonedx *CyclonedxConfig `yaml:"cyclonedx,omitempty" json:"cyclonedx,omitempty"`
	Grype     *GrypeConfig     `yaml:"grype,omitempty" json:"grype,omitempty"`
	Semgrep   *SemgrepConfig   `yaml:"semgrep,omitempty" json:"semgrep,omitempty"`
	Gitleaks  *GitleaksConfig  `yaml:"gitleaks,omitempty" json:"gitleaks,omitempty"`
}

// Declared returns the reports in the config file that aren't nil
func (c *Config) Declared() map[TypeID]any {
	declared := make(map[TypeID]any)
	if c.Cyclonedx != nil {
		declared[TypeCyclonedxSBOMReport] = c.Cyclonedx
	}
	if c.Grype != nil {
		declared[TypeGrypeScanReport] = c.Grype
	}
	if c.Semgrep != nil {
		declared[TypeSemgrepScanReport] = c.Semgrep
	}
	if c.Gitleaks != nil {
		declared[TypeGitleaksScanReport] = c.Gitleaks
	}
	return declared
}

func (c *Config) Required() []TypeID {
	required := make([]TypeID, 0)
	for k, v := range c.Declared() {
		if isRequired(v) {
			required = append(required, k)
		}
	}

	return required
}

// isRequired if v is not a valid type, will return false
func isRequired(v any) bool {
	switch v.(type) {
	case *CyclonedxConfig:
		return v.(*CyclonedxConfig).Required
	case *GrypeConfig:
		return v.(*GrypeConfig).Required
	case *SemgrepConfig:
		return v.(*SemgrepConfig).Required
	case *GitleaksConfig:
		return v.(*GitleaksConfig).Required
	default:
		return false
	}
}

func NewConfig() *Config {
	return &Config{
		Version:   "1",
		Cyclonedx: &CyclonedxConfig{Required: false, Critical: -1, High: -1, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1},
		Grype:     &GrypeConfig{Required: false, Critical: -1, High: -1, Medium: -1, Low: -1, Negligible: -1, Unknown: -1},
		Semgrep:   &SemgrepConfig{Required: false, Info: -1, Warning: -1, Error: -1},
		Gitleaks:  &GitleaksConfig{Required: false, SecretsAllowed: false},
	}
}

type ConfigReader struct {
	bytes.Buffer
}

func NewConfigReader(config *Config) (*ConfigReader, error) {
	if err := checkConfig(config); err != nil {
		return nil, err
	}

	reader := new(ConfigReader)

	// Errors caught in checkConfig
	_ = yaml.NewEncoder(reader).Encode(config)

	return reader, nil
}

func checkConfig(config *Config) error {
	if config == nil {
		return fmt.Errorf("%w: config to encode is nil", ErrNilObject)
	}

	if config.Version == "" {
		return fmt.Errorf("%w: version field cannot be blank", ErrFailedCheck)
	}
	return nil
}

type ConfigWriter struct {
	bytes.Buffer
}

func (d *ConfigWriter) Decode() (any, error) {

	config := new(Config)

	decoder := yaml.NewDecoder(d)
	decoder.KnownFields(true)
	if err := decoder.Decode(config); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}

	return config, checkConfig(config)
}

func Example() {

	reader, err := NewConfigReader(NewConfig())

	if err != nil {
		panic(err)
	}

	tempBuffer := new(bytes.Buffer)

	reader.WriteTo(tempBuffer)
	fmt.Println(tempBuffer.String())

	writer := new(ConfigWriter)
	writer.ReadFrom(tempBuffer)
	decodedConfig, err := writer.Decode()

	if err != nil {
		panic(err)
	}

	fmt.Println(decodedConfig.(*Config).Version)

	// Output:
	// version: "1"
	// 1
}
