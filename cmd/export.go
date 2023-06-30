package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
)

func NewExportCmd(
	ddService DDExportService,
	ddTimeout time.Duration,
	newAsyncDecoder func() AsyncDecoder,
	ddEngagement defectdojo.EngagementQuery,
	awsService AWSExportService,
	awsTimeout time.Duration,
) *cobra.Command {
	// gatecheck export command
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export a report to a target location",
	}

	// gatecheck export defect-dojo command
	defectDojoCmd := &cobra.Command{
		Use:     "defect-dojo [FILE]",
		Short:   "Export raw scan report to DefectDojo",
		Aliases: []string{"dd"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// fullBom, _ := cmd.Flags().GetBool("full-bom")
			// Open the file
			log.Infof("Opening file: %s", args[0])
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			log.Infof("Decoding file: %s", args[0])

			decoder := newAsyncDecoder()
			exportBuf := new(bytes.Buffer)
			multiWriter := io.MultiWriter(decoder, exportBuf)

			_, _ = io.Copy(multiWriter, f)
			obj, err := decoder.Decode()

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			var ddScanType defectdojo.ScanType
			switch obj.(type) {
			case *grype.ScanReport:
				ddScanType = defectdojo.Grype
			case *semgrep.ScanReport:
				ddScanType = defectdojo.Semgrep
			case *gitleaks.ScanReport:
				ddScanType = defectdojo.Gitleaks
			default:
				return fmt.Errorf("%w: Unsupported file type", ErrorEncoding)
			}

			// if rType != artifact.Cyclonedx && fullBom {
			// 	return errors.New("--full-bom is only permitted with a CycloneDx file")
			// }

			// if fullBom {
			// 	buf := bytes.NewBuffer(fileBytes)
			// 	c := artifact.DecodeJSONOld[artifact.CyclonedxSbomReport](buf)
			// 	fileBytes, _ = json.Marshal(c.ShimComponentsAsVulnerabilities())
			// }

			ctx, cancel := context.WithTimeout(context.Background(), ddTimeout)
			defer cancel()

			return ddService.Export(ctx, exportBuf, ddEngagement, ddScanType)
		},
	}

	// gatecheck export aws command
	awsCmd := &cobra.Command{
		Use:   "s3 [FILE]",
		Short: "Export raw scan report to AWS S3",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			objectKey, _ := cmd.Flags().GetString("key")

			ctx, cancel := context.WithTimeout(context.Background(), awsTimeout)
			defer cancel()

			return awsService.Export(ctx, f, objectKey)
		},
	}
	awsCmd.Flags().String("key", "", "The AWS S3 object key for the location in the bucket")
	awsCmd.MarkFlagRequired("key")

	exportCmd.PersistentFlags().BoolP("full-bom", "m", false, "CycloneDx: Adds all the components with no vulnerabilities as SeverityNone")
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(awsCmd)
	return exportCmd
}
