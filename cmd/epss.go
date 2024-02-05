package cmd

import (
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sort"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/format"
)

func newEPSSCmd(EPSSDownloadAgent io.Reader) *cobra.Command {

	var downloadCmd = &cobra.Command{
		Use:   "download",
		Short: "EPSS CSV with scores for all CVEs (outputs to STDOUT)",
		RunE: func(cmd *cobra.Command, args []string) error {

			n, err := io.Copy(cmd.OutOrStdout(), EPSSDownloadAgent)
			if err != nil {
				return err
			}

			slog.Info("write to STDOUT", "bytes_written", n)
			return nil
		},
	}

	var EPSSCmd = &cobra.Command{
		Use:   "epss <Grype FILE>",
		Short: "Query first.org for Exploit Prediction Scoring System (EPSS)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			var service *epss.Service

			csvFilename, _ := cmd.Flags().GetString("epss-file")
			fetchFlag, _ := cmd.Flags().GetBool("fetch")
			outputFormat, _ := cmd.Flags().GetString("format")

			if fetchFlag {
				service = epss.NewService(EPSSDownloadAgent)
			}

			if csvFilename != "" {
				service = epss.NewService(fileOrEmptyBuf(csvFilename))
			}

			if service == nil {
				return fmt.Errorf("%w: No EPSS file or --fetch flag", ErrorUserInput)
			}

			r, err := grype.NewReportDecoder().DecodeFrom(fileOrEmptyBuf(args[0]))

			if err != nil {
				return fmt.Errorf("%w: decoding grype file: %v", ErrorEncoding, err)
			}

			grypeScan := r.(*grype.ScanReport)

			if err := service.Fetch(); err != nil {
				return fmt.Errorf("service fetch error: %w", err)
			}
			cves, err := service.GetCVEs(grypeScan.Matches)
			if err != nil {
				return err
			}

			switch outputFormat {
			case "csv":
				// Create a CSV writer
				writer := csv.NewWriter(os.Stdout)
				defer writer.Flush()

				// Write header
				// {CVE-2023-32313 Medium https://nvd.nist.gov/vuln/detail/CVE-2023-32313 2024-02-04 00:00:00 +0000 +0000 0.00052 0.17625}
				header := []string{"CVE", "Severity", "EPSS Score", "Percentile", "Link"}
				if err := writer.Write(header); err != nil {
					panic(err)
				}

				// Write each EPSS score record
				for _, cve := range cves {
					row := []string{
						cve.ID,
						cve.Severity,
						strconv.FormatFloat(cve.Probability, 'f', -1, 64),
						strconv.FormatFloat(cve.Percentile, 'f', -1, 64),
						cve.Link,
					}
					if err := writer.Write(row); err != nil {
						panic(err)
					}
				}
				return nil
			default:
				_, err = format.NewTableWriter(epssTable(cves)).WriteTo(cmd.OutOrStderr())
				return err
			}
		},
	}

	EPSSCmd.AddCommand(downloadCmd)

	EPSSCmd.Flags().StringP("epss-file", "e", "", "A downloaded CSV File with scores, note: will not query API")
	EPSSCmd.Flags().Bool("fetch", false, "Fetch EPSS scores from API")
	EPSSCmd.Flags().StringP("format", "f", "", "Output format (default: table)")
	EPSSCmd.MarkFlagsMutuallyExclusive("epss-file", "fetch")

	return EPSSCmd
}

func epssTable(input []epss.CVE) *format.Table {

	table := format.NewTable()

	table.AppendRow("CVE", "Severity", "EPSS Score", "Percentile", "Link")

	for _, cve := range input {
		prob := "-"
		perc := "-"
		if cve.Probability != 0 {
			prob = fmt.Sprintf("%.5f", cve.Probability)
		}
		if cve.Percentile != 0 {
			perc = fmt.Sprintf("%.2f%%", 100*cve.Percentile)
		}
		table.AppendRow(cve.ID, cve.Severity, prob, perc, cve.Link)
	}

	table.SetSort(2, func(a, b string) bool {
		return a > b
	})
	sort.Sort(table)

	return table
}
