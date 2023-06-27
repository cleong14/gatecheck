package bundle

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
	gcc "github.com/gatecheckdev/gatecheck/pkg/artifacts/config"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcs "github.com/gatecheckdev/gatecheck/pkg/strings"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const SupportedConfigVersion = "1.0.0"

type FileType string

type AnyDecoder interface {
	io.Writer
	Reset()
	Decode() (any, error)
	DecodeFrom(r io.Reader) (any, error)
	FileType() string
}

type AnyValidator interface {
	Validate(any, any) error
	ValidateFrom(io.Reader, io.Reader) error
}

type Bundle struct {
	Version   string
	Artifacts map[string][]byte
}

func NewBundle() *Bundle {
	return &Bundle{Version: "1", Artifacts: make(map[string][]byte)}
}

type PrettyWriter struct {
	w                 io.Writer
	asyncDecoder      AnyDecoder
	requiredFileTypes []string
}

func NewPrettyWriter(w io.Writer) *PrettyWriter {
	return &PrettyWriter{w: w}
}

func (p *PrettyWriter) WithAsyncDecoder(a AnyDecoder) *PrettyWriter {
	p.asyncDecoder = a
	return p
}

func (p *PrettyWriter) WithRequiredFileTypes(required []string) *PrettyWriter {
	p.requiredFileTypes = required
	return p
}

func (p *PrettyWriter) FileType(b []byte) string {
	p.asyncDecoder.Reset()
	_, _ = bytes.NewReader(b).WriteTo(p.asyncDecoder)
	_, _ = p.asyncDecoder.Decode()
	return p.asyncDecoder.FileType()
}

func (p *PrettyWriter) Encode(b *Bundle) error {
	table := new(gcs.Table).WithHeader("Type", "Label", "Digest", "Size", "Required")

	totalSize := uint64(0)
	for label, content := range b.Artifacts {

		totalSize += uint64(len(content))
		prettySize := humanize.Bytes(uint64(len(content)))
		digest := "sha256:" + strings.ToUpper(hex.EncodeToString(sha256.New().Sum(content)))
		fileType := "?"
		if p.asyncDecoder != nil {
			fileType = p.FileType(content)
		}
		required := ""
		for _, req := range p.requiredFileTypes {
			if fileType == req {
				required = "Y"
			}
		}
		table = table.WithRow(fileType, string(label), digest, prettySize, required)
	}

	horizontalLength := len(strings.Split(table.String(), "\n")[0])

	strings.NewReader(table.String() + "\n").WriteTo(p.w)

	summary := "Total Size: " + humanize.Bytes(totalSize)
	// Left pad with spaces
	line := strings.Repeat(" ", horizontalLength-len(summary)) + summary
	strings.NewReader(line).WriteTo(p.w)

	return nil
}

type Decoder struct {
	bytes.Buffer
}

func (d *Decoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}

	return d.Decode()
}

func (d *Decoder) Decode() (any, error) {
	reader, writer := io.Pipe()

	go func() {
		defer writer.Close()
		gzipReader, _ := gzip.NewReader(d)
		_, _ = io.Copy(writer, gzipReader)
	}()

	bundle := NewBundle()
	err := gob.NewDecoder(reader).Decode(bundle)

	return bundle, err
}

type Encoder struct {
	writer io.Writer
}

func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{writer: w}
}

func (r *Encoder) Encode(b *Bundle) error {

	reader, writer := io.Pipe()

	go func() {
		defer writer.Close()
		_ = gob.NewEncoder(writer).Encode(b)
	}()

	gzipWriter := gzip.NewWriter(r.writer)

	_, _ = io.Copy(gzipWriter, reader)

	gzipWriter.Close()
	return nil
}


type ArtifactValidator struct {
	validator AnyValidator
	fileType  FileType
	fieldName gcc.FieldName
}

func NewArtifactValidator(fileType string, fieldName string, validator AnyValidator) *ArtifactValidator {
	return &ArtifactValidator{fileType: FileType(fileType), fieldName: gcc.FieldName(fieldName), validator: validator}
}

func (v *ArtifactValidator) Validate(obj any, config any) error {
	return v.validator.Validate(obj, config)
}
func (v *ArtifactValidator) ValidateFrom(objReader io.Reader, configReader io.Reader) error {
	return v.validator.ValidateFrom(objReader, configReader)
}

type Validator struct {
	bundleDecoder *Decoder
	configDecoder *gcc.Decoder
	validators    []*ArtifactValidator
	asyncDecoder  AnyDecoder
}

func NewValidator(validators []*ArtifactValidator, asyncDecoder AnyDecoder) *Validator {
	return &Validator{bundleDecoder: new(Decoder), configDecoder: new(gcc.Decoder), validators: validators, asyncDecoder: asyncDecoder}
}

func (v *Validator) Validate(obj any, config any) error {
	bundle, ok := obj.(*Bundle)
	if !ok {
		return fmt.Errorf("%w: obj is %T", gce.ErrIO, obj)
	}
	gcConfig, ok := config.(*gcc.Config)
	if !ok {
		return fmt.Errorf("%w: config is %T", gce.ErrIO, config)
	}

	type artifactWithMetadata struct {
		object   any
		fileType FileType
	}

	decodedArtifacts := make(map[string]artifactWithMetadata)

	for label, artifactBytes := range bundle.Artifacts {
		v.asyncDecoder.Reset()
		obj, _ := v.asyncDecoder.DecodeFrom(bytes.NewReader(artifactBytes))
		ft := v.asyncDecoder.FileType()
		decodedArtifacts[label] = artifactWithMetadata{fileType: FileType(ft), object: obj}
	}

	validationErrors := make(map[string]error)

	for fieldName, configArtifact := range gcConfig.Artifacts {
		for _, validator := range v.validators {
			if fieldName != validator.fieldName {
				continue
			}
			for bundleLabel, bundleArtifact := range decodedArtifacts {
				if validator.fileType != bundleArtifact.fileType {
					continue
				}
				err := validator.Validate(bundleArtifact.object, configArtifact)
				if err != nil {
					validationErrors[bundleLabel] = err
				}
			}
		}
	}
	if len(decodedArtifacts) == 0 {
		return nil
	}
	returnErrors := []error{}

	for label, err := range validationErrors {
		returnErrors = append(returnErrors, fmt.Errorf("[%s]: %w", label, err))
	}

	err := errors.Join(returnErrors...)

	return fmt.Errorf("%w: %v", gcv.ErrValidation, err)
}

func (v *Validator) ValidateFrom(objReader io.Reader, configReader io.Reader) error {
	bundle, err := v.bundleDecoder.DecodeFrom(objReader)
	if err != nil {
		return fmt.Errorf("%w: object is not a Gatecheck bundle", gce.ErrIO)
	}
	config, err := v.configDecoder.DecodeFrom(objReader)
	if err != nil {
		return fmt.Errorf("%w: object is not a Gatecheck config", gce.ErrIO)
	}

	return v.Validate(bundle, config)
}
