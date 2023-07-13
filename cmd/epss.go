package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/spf13/cobra"
)

func NewEPSSCmd(service EPSSService) *cobra.Command {

	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "EPSS CSV with scores for all CVEs (outputs to STDOUT)",
		RunE: func(cmd *cobra.Command, args []string) error {
			url, _ := cmd.Flags().GetString("url")

			n, err := service.WriteCSV(cmd.OutOrStdout(), url)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorAPI, err)
			}

			log.Infof("%d bytes written to STDOUT", n)
			return nil
		},
	}

	today := time.Now()
	defaultURL := fmt.Sprintf("https://epss.cyentia.com/epss_scores-%d-%s-%s.csv.gz", today.Year(), today.Format("01"), today.Format("02"))
	downloadCmd.Flags().StringP("url", "u", defaultURL, "The URL for the CSV file")

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var csvFile *os.File
			var err error

			csvFilename, _ := cmd.Flags().GetString("file")

			grypeFile, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if csvFilename != "" {
				csvFile, err = os.Open(csvFilename)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
			}

			r, err := grype.NewReportDecoder().DecodeFrom(grypeFile)

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			grypeScan := r.(*grype.ScanReport)

			cves := cvesFromGrypeReport(grypeScan)

			if csvFile != nil {
				err = epssFromDataStore(csvFile, cves)
			} else {
				err = epssFromAPI(service, cves)
			}

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorAPI, err)
			}

			cmd.Println(epss.Sprint(cves))

			return err
		},
	}

	EPSSCmd.AddCommand(downloadCmd)

	EPSSCmd.Flags().StringP("file", "f", "", "A downloaded CSV File with scores, note: will not query API")

	return EPSSCmd
}

func cvesFromGrypeReport(report *grype.ScanReport) []epss.CVE {

	cves := make([]epss.CVE, len(report.Matches))

	for i, match := range report.Matches {
		cves[i] = epss.CVE{
			ID:       match.Vulnerability.ID,
			Severity: match.Vulnerability.Severity,
			Link:     match.Vulnerability.DataSource,
		}
	}
	return cves
}

func epssFromAPI(service EPSSService, CVEs []epss.CVE) error {

	err := service.WriteEPSS(CVEs)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrorAPI, err)
	}

	return nil
}

func epssFromDataStore(epssCSV io.Reader, CVEs []epss.CVE) error {
	store := epss.NewDataStore()
	if err := epss.NewCSVDecoder(epssCSV).Decode(store); err != nil {
		return fmt.Errorf("%w: decoding EPSS CSV", err)
	}
	log.Infof("EPSS CSV Datastore imported scores for %d CVEs\n", store.Len())

	if err := store.WriteEPSS(CVEs); err != nil {
		return fmt.Errorf("%w: Writing EPSS scores from Data Store", err)

	}

	return nil
}
