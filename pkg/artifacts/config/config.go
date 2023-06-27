package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"gopkg.in/yaml.v3"
	// gcs "github.com/gatecheckdev/gatecheck/pkg/strings"
	// gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const SupportedConfigVersion = "1"
const ConfigFileType = "Gatecheck Config"

type FieldName string

type Config struct {
	Version   string `yaml:"version"`
	Artifacts map[FieldName]any
}

type Decoder struct {
	bytes.Buffer
	decoders map[FieldName]gce.WriterDecoder
}

func (d *Decoder) WithSubDecoders(f map[FieldName]gce.WriterDecoder) *Decoder {
	d.decoders = f
	return d
}

func (d *Decoder) Decode() (any, error) {

	data := map[string]any{}
	if err := yaml.NewDecoder(d).Decode(data); err != nil {
		return nil, err
	}

	version, ok := data["version"]
	if !ok {
		return nil, errors.New("missing version field")
	}
	if version != SupportedConfigVersion {
		return nil, fmt.Errorf("%w: version '%s' is not supported. Support version is '%s'", gce.ErrFailedCheck, version, SupportedConfigVersion)
	}

	config := &Config{Version: SupportedConfigVersion, Artifacts: make(map[FieldName]any)}

	if d.decoders == nil {
		return config, nil
	}

	for fieldName := range d.decoders {
		if string(fieldName) == "version" {
			continue
		}

		// Convert back to a string so it can be decoded by the proper decoder
		err := yaml.NewEncoder(d.decoders[fieldName]).Encode(map[FieldName]any{fieldName: data[string(fieldName)]})
		if err != nil {
			return nil, fmt.Errorf("%w: %v",gce.ErrEncoding, err)
		}

		obj, err := d.decoders[fieldName].Decode()
		if err != nil {
			return config, err
		}

		config.Artifacts[fieldName] = obj
	}

	return config, nil
}

func (d *Decoder) DecodeFrom(r io.Reader) (any, error) {
	if _, err := d.ReadFrom(r); err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	return d.Decode()
}

func (d *Decoder) FileType() string {
	return ConfigFileType
}
