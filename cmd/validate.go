package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/kev"

	"github.com/spf13/cobra"
)

type AnyValidator interface {
	Validate(objPtr any, configReader io.Reader) error
	ValidateFrom(objReader io.Reader, configReader io.Reader) error
}

func NewValidateCmd(newAsyncDecoder func() AsyncDecoder, KEVDownloadURL string, client *http.Client) *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var validationError error = nil

			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("kev-file")
			downloadKEVFlag, _ := cmd.Flags().GetBool("fetch-kev")
			auditFlag, _ := cmd.Flags().GetBool("audit")

			objFile, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			obj, err := newAsyncDecoder().DecodeFrom(objFile)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			configFileBytes, err := os.ReadFile(configFilename)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			validationError = validateAny(obj, configFileBytes, args[0], newAsyncDecoder)

			checkAuditFlag := func(err error) error {
				if err != nil && auditFlag {
					log.Warnf("audit flag detected, supressing error: %v", err)
					return nil
				}
				if err == nil {
					return nil
				}
				return fmt.Errorf("%w: %v", ErrorValidation, err)
			}

			// Return early if no KEV file passed
			if kevFilename == "" && downloadKEVFlag == false {
				return checkAuditFlag(validationError)
			}
			grypeReport, ok := obj.(*grype.ScanReport)
			if !ok {
				return checkAuditFlag(validationError)
			}

			// Only validate KEV with Grype reports
			var service *kev.Service

			switch downloadKEVFlag {
			case true:
				var err error
				service, err = kev.NewServiceFromAPI(KEVDownloadURL, client)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorAPI, err)
				}
			case false:
				kevFile, err := os.Open(kevFilename)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}

				service, err = kev.NewServiceFromFile(kevFile)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
				log.Infof("%d KEVs loaded from file", len(service.Catalog().Vulnerabilities))
			}

			_, _ = service.WithReport(grypeReport).WriteTo(cmd.ErrOrStderr())
			if len(service.MatchedVulnerabilities()) > 0 {
				validationError = fmt.Errorf("%d vulnerabilities on KEV Catalog", len(service.MatchedVulnerabilities()))
			}

			if validationError != nil {
				return checkAuditFlag(validationError)
			}

			return nil
		},
	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")
	cmd.Flags().StringP("kev-file", "k", "", "A CISA KEV catalog file, JSON or CSV and cross reference Grype report")
	cmd.Flags().Bool("fetch-kev", false, "Download a CISA KEV catalog file and cross reference Grype report")

	_ = cmd.MarkFlagRequired("config")
	cmd.MarkFlagsMutuallyExclusive("kev-file", "fetch-kev")
	return cmd
}

func validateAny(obj any, configFileBytes []byte, reportFilename string, newAsyncDecoder func() AsyncDecoder) error {
	// Handle an artifact bundle, will recursively handle each artifact file
	if bundle, ok := obj.(*archive.Bundle); ok {
		validationErrors := make(map[string]error, 0)
		for label := range bundle.Manifest().Files {
			decoder := newAsyncDecoder()
			_, _ = bundle.WriteFileTo(decoder, label)
			obj, _ := decoder.Decode()
			if decoder.FileType() == gce.GenericFileType {
				continue
			}
			if err := validateAny(obj, configFileBytes, reportFilename, newAsyncDecoder); err != nil {
				validationErrors[label] = err
			}
		}

		if len(validationErrors) == 0 {
			return nil
		}
		validationError := ErrorValidation
		for k, v := range validationErrors {
			errors.Join(validationError, fmt.Errorf("bundle artifact file '%s': %w", k, v))
		}
		return validationError
	}

	var validator AnyValidator

	switch obj.(type) {
	case *grype.ScanReport:
		validator = grype.NewValidator()
	case *semgrep.ScanReport:
		validator = semgrep.NewValidator()
	case *gitleaks.ScanReport:
		validator = gitleaks.NewValidator()
	case *cyclonedx.ScanReport:
		validator = cyclonedx.NewValidator()
	}

	return validator.Validate(obj, bytes.NewReader(configFileBytes))
}
