package kev

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

const FileTypeCSV = "CISA KEV Catalog [CSV]"

type CSVDecoder struct {
	bytes.Buffer
}

func NewCSVDecoder() *CSVDecoder {
	return &CSVDecoder{}
}

func (d *CSVDecoder) Decode() (any, error) {
	catalog := &Catalog{Title: fmt.Sprintf("CISA KEV Catalog from local CSV File Decoded %s", time.Now().Format("2006-01-02T15:04")),
		CatalogVersion: "N/A", DateReleased: time.Now()}
	defer func(started time.Time) {
		log.Infof("KEV Catalog CSV decoding completed in %s", time.Since(started).String())
	}(time.Now())
	scanner := bufio.NewScanner(d)

	scanner.Scan()
	header := scanner.Text()
	expectedHeader := []string{"cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "shortDescription", "requiredAction", "dueDate", "notes"}
	headerParts := strings.Split(header, ",")

	if len(headerParts) != len(expectedHeader) {
		return nil, fmt.Errorf("%w: invalid header", gce.ErrEncoding)
	}

	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		for i, p := range parts {
			// Strip quotes
			if len(p) < 3 {
				parts[i] = ""
				continue
			}
			parts[i] = p[1 : len(p)-1]
		}
		vul := Vulnerability{
			CveID: parts[0], VendorProject: parts[1], Product: parts[2], VulnerabilityName: parts[3],
			DateAdded: parts[4], ShortDescription: parts[5], RequiredAction: parts[6], DueDate: parts[7], Notes: parts[8],
		}
		catalog.Vulnerabilities = append(catalog.Vulnerabilities, vul)
	}
	catalog.Count = len(catalog.Vulnerabilities)

	return catalog, nil
}

func (d *CSVDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := io.Copy(d, r)
	if err != nil {
		return nil, gce.ErrIO
	}
	return d.Decode()
}

func (d *CSVDecoder) FileType() string {
	return FileTypeCSV
}
