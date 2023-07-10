package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	ErrorFileAccess     = errors.New("file access")
	ErrorEncoding       = errors.New("encoding")
	ErrorValidation     = errors.New("validation")
	ErrorAPI            = errors.New("request API")
	ErrorUserInput      = errors.New("user error")
	GlobalVerboseOutput = false
)

type DDExportService interface {
	Export(context.Context, io.Reader, defectdojo.EngagementQuery, defectdojo.ScanType) error
}

type EPSSService interface {
	WriteCSV(w io.Writer, url string) (int64, error)
	WriteEPSS([]epss.CVE) error
}

type KEVService interface {
}

type AWSExportService interface {
	Export(context.Context, io.Reader, string) error
}

type AsyncDecoder interface {
	io.Writer
	Decode() (any, error)
	DecodeFrom(r io.Reader) (any, error)
	FileType() string
	Reset()
}

type CLIConfig struct {
	Version             string
	PipedInput          *os.File
	Client              *http.Client
	DefaultReport       string
	EPSSService         EPSSService
	DDExportService     DDExportService
	DDEngagement        defectdojo.EngagementQuery
	DDExportTimeout     time.Duration
	AWSExportService    AWSExportService
	AWSExportTimeout    time.Duration
	NewAsyncDecoderFunc func() AsyncDecoder
	NewValidatorFunc    func() AnyValidator
	KEVDownloadURL      string
}

func NewRootCommand(config CLIConfig) *cobra.Command {
	command := &cobra.Command{
		Use:     "gatecheck",
		Version: config.Version,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf(GatecheckLogo)
			return nil
		},
	}

	// Global Flags
	command.PersistentFlags().BoolVarP(&GlobalVerboseOutput, "verbose", "v", false, "Verbose debug output")

	// Commands
	command.AddCommand(NewVersionCmd(config.Version))
	command.AddCommand(NewPrintCommand(config.PipedInput, config.NewAsyncDecoderFunc))
	command.AddCommand(NewConfigCmd())
	command.AddCommand(NewValidateCmd(config.NewAsyncDecoderFunc, config.KEVDownloadURL, config.Client))
	command.AddCommand(NewEPSSCmd(config.EPSSService))
	command.AddCommand(
		NewExportCmd(
			config.DDExportService,
			config.DDExportTimeout,
			config.NewAsyncDecoderFunc,
			config.DDEngagement,
			config.AWSExportService,
			config.AWSExportTimeout,
		),
	)

	return command
}

func NewVersionCmd(version string) *cobra.Command {
	command := &cobra.Command{
		Use: "version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.Printf(GatecheckLogo)
			cmd.Println("A utility for aggregating, validating, and exporting vulnerability reports")
			cmd.Println("Version:", version)
			return nil
		},
	}

	return command
}

func NewConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Creates a new configuration file",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "prints a new configuration file.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			configMap := map[string]any{
				"version":                 "1",
				grype.ConfigFieldName:     grype.Config{},
				semgrep.ConfigFieldName:   semgrep.Config{},
				gitleaks.ConfigFieldName:  gitleaks.Config{},
				cyclonedx.ConfigFieldName: cyclonedx.Config{},
			}
			return yaml.NewEncoder(cmd.OutOrStdout()).Encode(configMap)
		},
	}

	cmd.AddCommand(initCmd)

	return cmd
}
