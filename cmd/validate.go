package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/fs"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/spf13/cobra"
)

func auditError(w io.Writer, err error, audit bool) error {
	if !audit && err != nil {
		return err
	}
	if audit && err != nil {
		_, _ = fmt.Fprint(w, err)
		return nil
	}
	return err
}

func NewValidateCmd(decodeTimeout time.Duration) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var kevCatalog artifact.KEVCatalog
			// var grypeScan artifact.GrypeScanReport

			var validationError error = nil

			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("kev")
			auditFlag, _ := cmd.Flags().GetBool("audit")

			c, err := fs.ReadDecodeFile(configFilename, new(artifact.ConfigWriter))

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			validator := artifact.NewValidator(*c.(*artifact.Config))

			_, err = fs.ReadFile(args[0], validator)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			// err = auditError(cmd.ErrOrStderr(), validator.Validate(), auditFlag)
			validationError = validator.Validate()

			// Return early if no KEV file passed
			if kevFilename == "" {
				return auditError(cmd.ErrOrStderr(), validationError, auditFlag)
			}

			kevFile, err := os.Open(kevFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			if err := json.NewDecoder(kevFile).Decode(&kevCatalog); err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Decode for Grype and return an error on fail because only grype can be validated with a blacklist
			// decoder := artifact.NewGrypeReportDecoder()
			// a, err := decoder.Decode()
			//
			// if err != nil {
			// 	return fmt.Errorf("%w: only Grype Reports are supported with KEV: %v", ErrorEncoding, err)
			// }
			//
			// vulnerabilities := blacklist.BlacklistedVulnerabilities(grypeScan, kevCatalog)
			//
			// cmd.Println(blacklist.StringBlacklistedVulnerabilities(kevCatalog.CatalogVersion, vulnerabilities))
			//
			// cmd.Println(fmt.Sprintf("%d Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist",
			// 	len(vulnerabilities)))
			//
			// if len(vulnerabilities) > 0 {
			// 	validationError = ErrorValidation
			// }
			//
			// if auditFlag == true {
			// 	return nil
			// }

			return validationError
		},
	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")
	cmd.Flags().StringP("blacklist", "k", "", "A CISA KEV Blacklist file")

	_ = cmd.MarkFlagRequired("config")
	return cmd
}

func ParseAndValidate(r io.Reader, config artifact.Config, timeout time.Duration) error {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rType, b, err := artifact.ReadWithContext(ctx, r)

	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(b)

	// No need to check decode errors since it's decoded in the DetectReportType Function
	switch rType {
	case artifact.Semgrep:
		if config.Semgrep == nil {
			return errors.New("no Semgrep configuration specified")
		}
		err = artifact.ValidateSemgrep(*config.Semgrep, artifact.DecodeJSONOld[artifact.SemgrepScanReport](buf))
	case artifact.Cyclonedx:
		if config.Cyclonedx == nil {
			return errors.New("no CycloneDx configuration specified")
		}
		err = artifact.ValidateCyclonedx(*config.Cyclonedx, artifact.DecodeJSONOld[artifact.CyclonedxSbomReport](buf))
	case artifact.Grype:
		if config.Grype == nil {
			return errors.New("no Grype configuration specified")
		}
		err = artifact.ValidateGrype(*config.Grype, artifact.DecodeJSONOld[artifact.GrypeScanReport](buf))
	case artifact.Gitleaks:
		if config.Gitleaks == nil {
			return errors.New("no Gitleaks configuration specified")
		}
		err = artifact.ValidateGitleaks(*config.Gitleaks, artifact.DecodeJSONOld[artifact.GitleaksScanReport](buf))
	case artifact.GatecheckBundle:
		var errStrings []string
		bundle := artifact.DecodeBundle(buf)
		if err := bundle.ValidateCyclonedx(config.Cyclonedx); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateGrype(config.Grype); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateSemgrep(config.Semgrep); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if err := bundle.ValidateGitleaks(config.Gitleaks); err != nil {
			errStrings = append(errStrings, err.Error())
		}
		if len(errStrings) == 0 {
			return nil
		}
		return errors.New(strings.Join(errStrings, "\n"))

	default:
		err = errors.New("unsupported scan type")
	}

	return err

}
