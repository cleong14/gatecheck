package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/log"
	archive "github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/spf13/cobra"
)

// NewPrintCommand will pretty print a report file table, r can be piped input from standard out
func NewPrintCommand(pipedFile *os.File, newAsyncDecoder func() AsyncDecoder) *cobra.Command {
	var command = &cobra.Command{
		Use:     "print [FILE ...]",
		Short:   "Pretty print a gatecheck report or security scan report",
		Example: "gatecheck print grype-report.json semgrep-report.json",
		RunE: func(cmd *cobra.Command, args []string) error {

			if pipedFile != nil {
				log.Infof("Piped File Received: %s", pipedFile.Name())
				v, _ := newAsyncDecoder().DecodeFrom(pipedFile)
				printArtifact(cmd.OutOrStdout(), v, newAsyncDecoder)
			}

			for _, v := range args {
				log.Infof("Opening file: %s", v)
				f, err := os.Open(v)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				v, _ := newAsyncDecoder().DecodeFrom(f)
				printArtifact(cmd.OutOrStdout(), v, newAsyncDecoder)
			}

			return nil
		},
	}

	return command
}

func printArtifact(w io.Writer, v any, newDecoder func() AsyncDecoder) {
	outputString := ""
	switch v.(type) {
	case *grype.ScanReport:
		outputString = v.(*grype.ScanReport).String()
	case *semgrep.ScanReport:
		outputString = v.(*semgrep.ScanReport).String()
	case *gitleaks.ScanReport:
		outputString = v.(*gitleaks.ScanReport).String()
	case *archive.Bundle:
		_ = archive.NewPrettyWriter(w).WithAsyncDecoder(newDecoder()).Encode(v.(*archive.Bundle))
		return
	}

	_, _ = strings.NewReader(outputString).WriteTo(w)

}
