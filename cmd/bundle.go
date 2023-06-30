package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/gatecheckdev/gatecheck/internal/log"
	archive "github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/spf13/cobra"
)

func NewBundleCmd() *cobra.Command {

	var extractCmd = &cobra.Command{
		Use:   "extract <GATECHECK BUNDLE>",
		Short: "Extract a specific file from a gatecheck bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			label, _ := cmd.Flags().GetString("label")
			if label == "" {
				return fmt.Errorf("%w: No label provided", ErrorUserInput)
			}

			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			bundle, err := new(archive.Decoder).DecodeFrom(f)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			artifactBytes := bundle.(*archive.Bundle).Artifacts[label]

			n, err := io.Copy(cmd.OutOrStdout(), bytes.NewReader(artifactBytes))
			log.Infof("%d bytes written to STDOUT", n)

			return err

		},
	}

	extractCmd.Flags().String("label", "", "The label of the file to extract from the bundle")
	extractCmd.MarkFlagRequired("label")

	var cmd = &cobra.Command{
		Use:   "bundle [FILE ...]",
		Short: "Add reports to Gatecheck Report",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Flag is required, ignore errors
			outputFilename, _ := cmd.Flags().GetString("output")
			flagAllowMissing, _ := cmd.Flags().GetBool("allow-missing")

			log.Infof("Opening target output Bundle file: %s", outputFilename)
			outputFile, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_RDWR, 0644)

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			var bundle *archive.Bundle

			decoder := new(archive.Decoder)
			// Attempt to decode the file into the bundle object
			if info, _ := outputFile.Stat(); info.Size() != 0 {
				log.Infof("Existing Bundle File Size: %d", info.Size())
				log.Infof("Decoding bundle...")
				decodedBundle, err := decoder.DecodeFrom(outputFile)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
				bundle = decodedBundle.(*archive.Bundle)
				log.Info("Successful bundle decode, new files will be added to existing bundle")
			}
			
			if bundle == nil {
				bundle = archive.NewBundle()
			}

			// Open each file, create a bundle artifact and add it to the bundle object
			for _, v := range args {
				log.Infof("Opening File: %s", v)
				b, err := os.ReadFile(v)
				if errors.Is(err, os.ErrNotExist) && flagAllowMissing {
					log.Warnf("%s does not exist, skipping", v)
					continue
				}

				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				label := path.Base(v)
				bundle.Artifacts[label] = b
			}

			_ = archive.NewPrettyWriter(cmd.OutOrStderr()).Encode(bundle)

			log.Info("Truncating existing file...")
			_ = outputFile.Truncate(0)
			_, _ = outputFile.Seek(0, 0)

			log.Info("Writing bundle to file...")
			// Finish by encoding the bundle to the file
			return archive.NewEncoder(outputFile).Encode(bundle)
		},
	}

	cmd.Flags().StringP("output", "o", "", "output filename")
	cmd.Flags().BoolP("allow-missing", "m", false, "Don't fail if a file doesn't exist")

	_ = cmd.MarkFlagFilename("output", "gatecheck")
	_ = cmd.MarkFlagRequired("output")

	cmd.AddCommand(extractCmd)
	return cmd
}
