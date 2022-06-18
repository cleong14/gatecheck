package grype

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

type Asset struct {
	Label string `json:"label"`
	scan  ScanReport
}

func NewAsset(label string) *Asset {
	return &Asset{
		Label: label,
	}
}

func (a Asset) WithScan(s ScanReport) *Asset {
	// Save the scan
	a.scan = s
	// Encode scan as JSON
	jsonBytes := new(bytes.Buffer)
	_ = json.NewEncoder(jsonBytes).Encode(&s)

	return &a
}

type AssetReader struct {
	reader io.Reader
}

func (r *AssetReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *AssetReader) ReadAsset() (*Asset, error) {
	// Create r data structure to decode the bytes into
	assetData := struct {
		Label   string `json:"label"`
		Content string `json:"content"`
	}{}
	// Decode the assetData into the temp data structure
	err := json.NewDecoder(r).Decode(&assetData)
	if err != nil {
		return nil, fmt.Errorf("error Decoding temp asset Data: %v", err)
	}

	// Decode the content from base64
	decodedContent, err := base64.StdEncoding.DecodeString(assetData.Content)

	// Create a zip reader used to unzip bytes
	zipReader, _ := gzip.NewReader(bytes.NewBuffer(decodedContent))

	// Read the unzipped bytes into a scan object
	scan, err := NewScanReportReader(zipReader).ReadScan()

	// Create a new asset, attach the decoded scan
	asset := NewAsset(assetData.Label).WithScan(*scan)

	return asset, err
}

func NewAssetReader(r io.Reader) *AssetReader {
	return &AssetReader{reader: r}
}

type AssetWriter struct {
	writer io.Writer
}

func (w *AssetWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *AssetWriter) WriteAsset(a *Asset) error {
	// Create data structure to write
	asset := struct {
		Label   string `json:"label"`
		Content string `json:"content"`
	}{
		a.Label,
		"",
	}

	// Zip the scan into a bytes buffer
	contentBuffer := new(bytes.Buffer)
	zipper, _ := gzip.NewWriterLevel(contentBuffer, gzip.BestCompression)

	// Write the scan to the zipper
	_ = NewScanReportWriter(zipper).WriteScan(a.scan)

	_ = zipper.Close()

	// Saved the zipped content
	asset.Content = base64.StdEncoding.EncodeToString(contentBuffer.Bytes())

	// Encode the temp structure to json
	return json.NewEncoder(w).Encode(&asset)
}

func NewAssetWriter(w io.Writer) *AssetWriter {
	return &AssetWriter{writer: w}
}

type ScanReportReader struct {
	reader io.Reader
}

func (r *ScanReportReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *ScanReportReader) ReadScan() (*ScanReport, error) {
	scan := &ScanReport{}
	err := json.NewDecoder(r).Decode(scan)

	return scan, err
}

func NewScanReportReader(r io.Reader) *ScanReportReader {
	return &ScanReportReader{reader: r}
}

type ScanReportWriter struct {
	writer io.Writer
}

func NewScanReportWriter(w io.Writer) *ScanReportWriter {
	return &ScanReportWriter{writer: w}
}

func (w *ScanReportWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *ScanReportWriter) WriteScan(scan ScanReport) error {
	return json.NewEncoder(w).Encode(scan)
}

type ScanReport struct {
	Matches []struct {
		Vulnerability struct {
			Id          string        `json:"id"`
			DataSource  string        `json:"dataSource"`
			Namespace   string        `json:"namespace"`
			Severity    string        `json:"severity"`
			Urls        []string      `json:"urls"`
			Description string        `json:"description,omitempty"`
			Cvss        []interface{} `json:"cvss"`
			Fix         struct {
				Versions []string `json:"versions"`
				State    string   `json:"state"`
			} `json:"fix"`
			Advisories []struct {
				Id   string `json:"id"`
				Link string `json:"link"`
			} `json:"advisories"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			Id          string   `json:"id"`
			DataSource  string   `json:"dataSource"`
			Namespace   string   `json:"namespace"`
			Severity    string   `json:"severity"`
			Urls        []string `json:"urls"`
			Description string   `json:"description"`
			Cvss        []struct {
				Version string `json:"version"`
				Vector  string `json:"vector"`
				Metrics struct {
					BaseScore           float64 `json:"baseScore"`
					ExploitabilityScore float64 `json:"exploitabilityScore"`
					ImpactScore         float64 `json:"impactScore"`
				} `json:"metrics"`
				VendorMetadata struct {
				} `json:"vendorMetadata"`
			} `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		MatchDetails []struct {
			Type       string `json:"type"`
			Matcher    string `json:"matcher"`
			SearchedBy struct {
				Distro struct {
					Type    string `json:"type"`
					Version string `json:"version"`
				} `json:"distro"`
				Namespace string `json:"namespace"`
				Package   struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"package"`
			} `json:"searchedBy"`
			Found struct {
				VersionConstraint string `json:"versionConstraint"`
			} `json:"found"`
		} `json:"matchDetails"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			Locations []struct {
				Path    string `json:"path"`
				LayerID string `json:"layerID"`
			} `json:"locations"`
			Language  string   `json:"language"`
			Licenses  []string `json:"licenses"`
			Cpes      []string `json:"cpes"`
			Purl      string   `json:"purl"`
			Upstreams []struct {
				Name    string `json:"name"`
				Version string `json:"version,omitempty"`
			} `json:"upstreams"`
		} `json:"artifact"`
	} `json:"matches"`
	Source struct {
		Type   string `json:"type"`
		Target struct {
			UserInput      string        `json:"userInput"`
			ImageID        string        `json:"imageID"`
			ManifestDigest string        `json:"manifestDigest"`
			MediaType      string        `json:"mediaType"`
			Tags           []interface{} `json:"tags"`
			ImageSize      int           `json:"imageSize"`
			Layers         interface{}   `json:"layers"`
			Manifest       interface{}   `json:"manifest"`
			Config         interface{}   `json:"config"`
			RepoDigests    []interface{} `json:"repoDigests"`
			Architecture   string        `json:"architecture"`
			Os             string        `json:"os"`
		} `json:"target"`
	} `json:"source"`
	Distro struct {
		Name    string   `json:"name"`
		Version string   `json:"version"`
		IdLike  []string `json:"idLike"`
	} `json:"distro"`
	Descriptor struct {
		Name          string `json:"name"`
		Version       string `json:"version"`
		Configuration struct {
			ConfigPath         string `json:"configPath"`
			Output             string `json:"output"`
			File               string `json:"file"`
			Distro             string `json:"distro"`
			AddCpesIfNone      bool   `json:"add-cpes-if-none"`
			OutputTemplateFile string `json:"output-template-file"`
			Quiet              bool   `json:"quiet"`
			CheckForAppUpdate  bool   `json:"check-for-app-update"`
			OnlyFixed          bool   `json:"only-fixed"`
			Platform           string `json:"platform"`
			Search             struct {
				Scope             string `json:"scope"`
				UnindexedArchives bool   `json:"unindexed-archives"`
				IndexedArchives   bool   `json:"indexed-archives"`
			} `json:"search"`
			Ignore  interface{}   `json:"ignore"`
			Exclude []interface{} `json:"exclude"`
			Db      struct {
				CacheDir              string `json:"cache-dir"`
				UpdateUrl             string `json:"update-url"`
				CaCert                string `json:"ca-cert"`
				AutoUpdate            bool   `json:"auto-update"`
				ValidateByHashOnStart bool   `json:"validate-by-hash-on-start"`
			} `json:"db"`
			Dev struct {
				ProfileCpu bool `json:"profile-cpu"`
				ProfileMem bool `json:"profile-mem"`
			} `json:"dev"`
			FailOnSeverity string `json:"fail-on-severity"`
			Registry       struct {
				InsecureSkipTlsVerify bool          `json:"insecure-skip-tls-verify"`
				InsecureUseHttp       bool          `json:"insecure-use-http"`
				Auth                  []interface{} `json:"auth"`
			} `json:"registry"`
			Log struct {
				Structured bool   `json:"structured"`
				Level      string `json:"level"`
				File       string `json:"file"`
			} `json:"log"`
		} `json:"configuration"`
		Db struct {
			Built         time.Time   `json:"built"`
			SchemaVersion int         `json:"schemaVersion"`
			Location      string      `json:"location"`
			Checksum      string      `json:"checksum"`
			Error         interface{} `json:"error"`
		} `json:"db"`
	} `json:"descriptor"`
}
