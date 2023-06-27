package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/spf13/cobra"
)

// NewPrintCommand will pretty print a report file table, r can be piped input from standard out
func NewPrintCommand(decodeTimeout time.Duration, pipedFile *os.File) *cobra.Command {
	var command = &cobra.Command{
		Use:     "print [FILE ...]",
		Short:   "Pretty print a gatecheck report or security scan report",
		Example: "gatecheck print grype-report.json semgrep-report.json",
		RunE: func(cmd *cobra.Command, args []string) error {

			decoder := new(artifact.AsyncDecoder)

			if pipedFile != nil {
				log.Infof("Piped File Received: %s", pipedFile.Name())
				if _, err := decoder.ReadFrom(pipedFile); err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), decodeTimeout)
				defer cancel()
				v, _ := decoder.Decode(ctx)
				printArtifact(cmd.OutOrStdout(), v)
			}

			for _, v := range args {
				log.Infof("Opening file: %s", v)
				ctx, cancel := context.WithTimeout(context.Background(), decodeTimeout)
				defer cancel()
				f, err := os.Open(v)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				decoder = new(artifact.AsyncDecoder)
				if _, err := decoder.ReadFrom(f); err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				v, _ := decoder.Decode(ctx)
				printArtifact(cmd.OutOrStdout(), v)
			}

			return nil
		},
	}

	return command
}

func printArtifact(w io.Writer, v any) {
	outputString := ""
	switch v.(type) {
	case *artifact.CyclonedxSbomReport:
		outputString = v.(*artifact.CyclonedxSbomReport).String()
	case *artifact.SemgrepScanReport:
		outputString = v.(*artifact.SemgrepScanReport).String()
	case *artifact.GrypeScanReport:
		outputString = v.(*artifact.GrypeScanReport).String()
	case *artifact.GitleaksScanReport:
		outputString = v.(*artifact.GitleaksScanReport).String()
	case *artifact.Bundle:
		outputString = v.(*artifact.Bundle).String()
	}

	_, _ = strings.NewReader(outputString).WriteTo(w)

}

