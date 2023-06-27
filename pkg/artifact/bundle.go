package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/dustin/go-humanize"
	gs "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type Bundle struct {
	Version   string
	Artifacts map[string]Artifact
	config    *Config
}

func NewBundle(artifacts ...Artifact) *Bundle {
	bundle := &Bundle{
		Version:   "1",
		Artifacts: make(map[string]Artifact),
	}

	configLabel := ""
	for _, a := range artifacts {
		bundle.Artifacts[a.Label] = a
		if a.Type == TypeGatecheckConfig {
			configLabel = a.Label
		}
	}

	if configLabel == "" {
		return bundle
	}

	writer := new(ConfigWriter)
	writer.ReadFrom(bytes.NewReader(bundle.Artifacts[configLabel].Content))

	// Can't error if NewArtifact was init'd correctly
	c, _ := writer.Decode()
	bundle.config = c.(*Config)

	return bundle
}

func (b *Bundle) SetConfig(c *Config) {
	b.config = c
}

func (b *Bundle) isRequired(a Artifact) string {
	if b.config == nil {
		return ""
	}

	for _, typeID := range b.config.Required() {
		if a.Type == typeID {
			return "Y"
		}
	}

	return ""
}

func (b *Bundle) String() string {
	table := new(gs.Table).WithHeader("Type", "Label", "Digest", "Size", "Required")

	totalSize := uint64(0)
	for _, v := range b.Artifacts {

		totalSize += uint64(len(v.ContentBytes()))
		prettySize := humanize.Bytes(uint64(len(v.ContentBytes())))
		table = table.WithRow(string(v.Type), v.Label, v.DigestString(), prettySize, b.isRequired(v))
	}

	horizontalLength := len(strings.Split(table.String(), "\n")[0])

	var sb strings.Builder
	sb.WriteString(table.String() + "\n")

	summary := "Total Size: " + humanize.Bytes(totalSize)
	// Left pad with spaces
	sb.WriteString(strings.Repeat(" ", horizontalLength-len(summary)) + summary)
	return sb.String()
}

// BundleReader converts a bundle into a gzip'd binary gob. implements io.writer via internal buffer
type BundleReader struct {
	bytes.Buffer
}

func NewBundleReader(bundle *Bundle) *BundleReader {
	bundleReader := new(BundleReader)
	reader, writer := io.Pipe()

	go func() {
		defer writer.Close()
		_ = gob.NewEncoder(writer).Encode(bundle)
	}()

	gzipWriter := gzip.NewWriter(bundleReader)

	_, _ = io.Copy(gzipWriter, reader)

	gzipWriter.Close()

	return bundleReader
}

type BundleWriter struct {
	bytes.Buffer
}

func (w *BundleWriter) Decode() (any, error) {

	buf := new(bytes.Buffer)

	gzipReader, err := gzip.NewReader(w)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	_, _ = buf.ReadFrom(gzipReader)

	bundle := new(Bundle)

	if err := gob.NewDecoder(buf).Decode(bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}

	for _, a := range bundle.Artifacts {
		if a.Type == TypeGatecheckConfig {
			writer := new(ConfigWriter)
			writer.ReadFrom(bytes.NewReader(a.Content))
			c, _ := writer.Decode()
			bundle.config = c.(*Config)
		}
	}

	return bundle, nil
}

func ValidateBundlePtr(config Config, report any) error {
	bundle, ok := report.(*Bundle)
	if !ok {
		return fmt.Errorf("%w: %T is an invalid report type", ErrValidation, bundle)
	}
	for _, required := range config.Required() {
		for _, a := range bundle.Artifacts {
			if a.Type == required {
				continue
			}
			return fmt.Errorf("%w: %s is required but bundle does not contain this type of artifact", ErrValidation, required)
		}
	}

	type result struct {
		err error
	}

	resultChan := make(chan result, len(bundle.Artifacts))
	var wg sync.WaitGroup

	for _, a := range bundle.Artifacts {
		wg.Add(1)
		go func(targetArtifact Artifact) {
			defer wg.Done()
			// Needed for now since the validators map in artifact.go calls this function
			validatorFuncs := map[TypeID]ValidateFunction{
				TypeGrypeScanReport:     ValidateGrypePtr,
				TypeSemgrepScanReport:   ValidateSemgrepPtr,
				TypeGitleaksScanReport:  ValidateGitleaksPtr,
				TypeCyclonedxSBOMReport: ValidateCyclonedxPtr,
			}
			validator := Validator{config: config, validatorFuncs: validatorFuncs}
			_, _ = validator.ReadFrom(bytes.NewReader(targetArtifact.ContentBytes()))
			if err := validator.Validate(); err != nil {
				resultChan <- result{err: fmt.Errorf("bundle artifact '%s': %w", targetArtifact.Label, err)}
				return
			}
			resultChan <- result{err: nil}
		}(a)
	}
	wg.Wait()
	close(resultChan)

	errs := make([]error, 0)
	for res := range resultChan {
		if res.err != nil {
			errs = append(errs, res.err)
		}
	}

	returnErr := errors.Join(errs...)
	if returnErr != nil {
		return fmt.Errorf("%w: %v", ErrValidation, returnErr)
	}

	return nil
}

func ExampleBundle() {
	// Creating a bundle
	artifact1, _ := NewArtifact("somefile.txt", strings.NewReader("some content"))
	bundle := NewBundle(artifact1)

	// Using the bundle reader
	buffer := new(bytes.Buffer)
	_, err := NewBundleReader(bundle).WriteTo(buffer)

	if err != nil {
		panic(err)
	}

	// Using the Bundle writer/decoder
	writerDecoder := new(BundleWriter)
	_, _ = buffer.WriteTo(writerDecoder)

	decodedObj, err := writerDecoder.Decode()

	decodedbundle := decodedObj.(*Bundle)

	fmt.Println(decodedbundle.Version)

	// Output: 1

}
