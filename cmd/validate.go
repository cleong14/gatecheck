package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"

	"github.com/spf13/cobra"
)

type AnyValidator interface {
	Validate(objPtr any, configReader io.Reader) error
	ValidateFrom(objReader io.Reader, configReader io.Reader) error
}

type epssScoreWriter interface {
	WriteEPSS([]epss.CVE) error
}

func NewValidateCmd(newAsyncDecoder func() AsyncDecoder, KEVDownloadURL string, client *http.Client, epssService EPSSService) *cobra.Command {
	var validateAny func(obj any, configBytes []byte) error

	var kevFile *os.File
	var epssFile *os.File

	var kevService *kev.Service
	var epssWriter epssScoreWriter

	var cmd = &cobra.Command{
		Use:   "validate [FILE]",
		Short: "Validate reports or a bundle using thresholds set in the Gatecheck configuration file",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			configFilename, _ := cmd.Flags().GetString("config")
			kevFilename, _ := cmd.Flags().GetString("kev-file")
			epssFilename, _ := cmd.Flags().GetString("epss-file")

			auditFlag, _ := cmd.Flags().GetBool("audit")
			kevFetchFlag, _ := cmd.Flags().GetBool("fetch-kev")
			epssFetchFlag, _ := cmd.Flags().GetBool("fetch-epss")

			objFile, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: Report / bundle: %v", ErrorFileAccess, err)
			}

			decoder := newAsyncDecoder()
			obj, err := decoder.DecodeFrom(objFile)
			if err != nil {
				return fmt.Errorf("%w: Async decoding: %v", ErrorEncoding, err)
			}

			configFileBytes, err := os.ReadFile(configFilename)
			if err != nil {
				return fmt.Errorf("%w: config file: %v", ErrorFileAccess, err)
			}

			if kevFilename != "" {
				kevFile, err = os.Open(kevFilename)
				if err != nil {
					return fmt.Errorf("%w: KEV file: %v", ErrorFileAccess, err)
				}
				kevService, err = kev.NewServiceFromFile(kevFile)
				if err != nil {
					return fmt.Errorf("%w: KEV service: %v", ErrorEncoding, err)
				}
			} else if kevFetchFlag {
				kevService, err = kev.NewServiceFromAPI(KEVDownloadURL, client)
				if err != nil {
					return fmt.Errorf("%w: KEV service: %v", ErrorAPI, err)
				}
			}

			if epssFilename != "" {
				epssFile, err = os.Open(epssFilename)
				if err != nil {
					return fmt.Errorf("%w: EPSS file: %v", ErrorFileAccess, err)
				}
				epssDataStore := epss.NewDataStore()
				if err := epss.NewCSVDecoder(epssFile).Decode(epssDataStore); err != nil {
					return fmt.Errorf("%w: EPSS file decoding: %v", ErrorEncoding, err)
				}
				epssWriter = epssDataStore
			} else if epssFetchFlag {
				epssWriter = epssService
			}

			err = validateAny(obj, configFileBytes)
			if err != nil && !errors.Is(err, gcv.ErrValidation) {
				return err
			}

			if err != nil && auditFlag {
				cmd.PrintErrf("[Audit]: %v\n", err)
				return nil
			}

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorValidation, err)
			}
			return nil

		},
	}

	validateAny = func(obj any, configBytes []byte) error {
		if bundle, ok := obj.(*archive.Bundle); ok {
			validationErrors := make(map[string]error, 0)
			for label := range bundle.Manifest().Files {
				decoder := newAsyncDecoder()
				_, _ = bundle.WriteFileTo(decoder, label)
				obj, _ := decoder.Decode()
				if decoder.FileType() == gce.GenericFileType {
					continue
				}
				if err := validateAny(obj, configBytes); err != nil {
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

		switch obj.(type) {

		case *semgrep.ScanReport:
			return semgrep.NewValidator().Validate(obj, bytes.NewReader(configBytes))
		case *gitleaks.ScanReport:
			return gitleaks.NewValidator().Validate(obj, bytes.NewReader(configBytes))
		case *cyclonedx.ScanReport:
			return cyclonedx.NewValidator().Validate(obj, bytes.NewReader(configBytes))
		}

		// This function is called after the async decoder so it has to be a defined type
		report := obj.(*grype.ScanReport)
		var kevValidationErr, epssValidationErr error
		if kevService != nil {
			kevValidationErr = kev.NewValidator(kevService).Validate(report, bytes.NewReader(configBytes))
		}
		if epssWriter != nil {
			// EPSS Validation modifies the report by removing approved vulnerabilities
			epssValidationErr = epss.NewValidator(epssWriter).Validate(report, bytes.NewReader(configBytes))
			if !errors.Is(epssValidationErr, gcv.ErrValidation) && epssValidationErr != nil {
				return fmt.Errorf("%w: %v", ErrorAPI, epssValidationErr)
			}
		}
		return errors.Join(kevValidationErr, epssValidationErr, grype.NewValidator().Validate(report, bytes.NewBuffer(configBytes)))

	}

	cmd.Flags().Bool("audit", false, "Exit w/ Code 0 even if validation fails")
	cmd.Flags().StringP("config", "c", "", "A Gatecheck configuration file with thresholds")

	cmd.Flags().StringP("kev-file", "k", "", "A CISA KEV catalog file, JSON or CSV and cross reference Grype report")
	cmd.Flags().Bool("fetch-kev", false, "Download a CISA KEV catalog file and cross reference Grype report")

	cmd.Flags().StringP("epss-file", "e", "", "A downloaded CSV File with scores, note: will not query API")
	cmd.Flags().Bool("fetch-epss", false, "Download EPSS scores from API")

	_ = cmd.MarkFlagRequired("config")
	cmd.MarkFlagsMutuallyExclusive("kev-file", "fetch-kev")
	cmd.MarkFlagsMutuallyExclusive("epss-file", "fetch-epss")
	return cmd
}
