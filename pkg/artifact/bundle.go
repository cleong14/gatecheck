package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"fmt"
	"strings"

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

type BundleReader struct {
	bytes.Buffer
}

func NewBundleReader(bundle *Bundle) (*BundleReader, error) {
	bundleReader := new(BundleReader)

	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(bundle); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}

	gzipWriter := gzip.NewWriter(bundleReader)
	buf.WriteTo(gzipWriter)

	gzipWriter.Close()

	return bundleReader, nil
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
	return bundle, nil
}

func ExampleBundle() {
	// Creating a bundle
	artifact1, _ := NewArtifact("somefile.txt", strings.NewReader("some content"))
	bundle := NewBundle(artifact1)

	// Using the bundle reader
	reader, err := NewBundleReader(bundle)
	if err != nil {
		panic(err)
	}

	buffer := new(bytes.Buffer)
	buffer.ReadFrom(reader)

	// Using the Bundle writer/decoder
	writerDecoder := new(BundleWriter)
	_, _ = buffer.WriteTo(writerDecoder)

	decodedObj, err := writerDecoder.Decode()

	decodedbundle := decodedObj.(*Bundle)

	fmt.Println(decodedbundle.Version)

	// Output: 1

}
