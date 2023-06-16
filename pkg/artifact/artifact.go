package artifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
)

type TypeID string

const (
	TypeGrypeScanReport     TypeID = "Anchore Grype Report"
	TypeSemgrepScanReport          = "Semgrep Report"
	TypeGitleaksScanReport         = "Gitleaks Scan Report"
	TypeCyclonedxSBOMReport        = "CycloneDX SBOM Report"
	TypeGatecheckConfig            = "Gatecheck Config"
	TypeGatecheckBundle            = "Gatecheck Bundle"
	TypeGeneric                    = "Generic"
)

func StandardDecoders() []WriterDecoder {
	return []WriterDecoder{
		NewGrypeReportDecoder(),
		NewSemgrepReportDecoder(),
		NewGitleaksReportDecoder(),
		NewCyclonedxSbomReportDecoder(),
		new(ConfigWriter),
		new(BundleWriter),
	}
}

type Artifact struct {
	Label   string
	Type    TypeID
	Digest  []byte
	Content []byte
}

func (a Artifact) String() string {
	return fmt.Sprintf("%s (%s) [%s] %s", a.Label, a.Type, a.DigestString(), humanize.Bytes(uint64(len(a.Content))))
}

func (a Artifact) DigestString() string {
	return "sha256:" + strings.ToUpper(hex.EncodeToString(a.Digest))
}

func (a Artifact) ContentBytes() []byte {
	return append([]byte{}, a.Content...)
}

func NewArtifact(label string, r io.Reader) (Artifact, error) {

	hashWriter := sha256.New()
	decoder := new(AsyncDecoder).WithDecoders(StandardDecoders()...)
	outputBuf := new(bytes.Buffer)

	// Hash the file
	multiWriter := io.MultiWriter(hashWriter, decoder, outputBuf)

	if _, err := io.Copy(multiWriter, r); err != nil {
		return Artifact{}, fmt.Errorf("%w: %v", ErrEncoding, err)
	}

	v, _ := decoder.Decode(context.Background())

	return Artifact{
		Label:   label,
		Digest:  hashWriter.Sum(nil),
		Type:    GatecheckTypeID(v),
		Content: outputBuf.Bytes(),
	}, nil
}

func GatecheckTypeID(v any) TypeID {

	switch v.(type) {
	case *GrypeScanReport:
		return TypeGrypeScanReport
	case *SemgrepScanReport:
		return TypeSemgrepScanReport
	case *GitleaksScanReport:
		return TypeGitleaksScanReport
	case *CyclonedxSbomReport:
		return TypeCyclonedxSBOMReport
	case *Config:
		return TypeGatecheckConfig
	case *Bundle:
		return TypeGatecheckBundle
	default:
		return TypeGeneric
	}
}

func ExampleArtifact() {
	foo, err := NewArtifact("foo.txt", strings.NewReader("some content"))
	if err != nil {
		panic(err)
	}
	fmt.Println(string(foo.Content))

	// Output: some content
}
