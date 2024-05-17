package cmd

import (
	"io"
	"os"
	"strings"

	"github.com/gatecheckdev/configkit"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var (
	metadataFlagUsage       = "flag_usage"
	metadataFieldType       = "field_type"
	metadataRequired        = "required"
	metadataActionInputName = "action_input_name"
)

type Config struct {
	BundleTag string
	EPSSURL   string
	KEVURL    string
}

type metaConfig struct {
	BundleTag          configkit.MetaField
	EPSSURL            configkit.MetaField
	KEVURL             configkit.MetaField
	EPSSFilename       configkit.MetaField
	Verbose            configkit.MetaField
	Silent             configkit.MetaField
	BundleTagValue     []string
	bundleFile         *os.File
	targetFile         *os.File
	epssFile           *os.File
	listSrcReader      io.Reader
	listSrcName        string
	listFormat         string
	listAll            bool
	configOutputWriter io.Writer
	configOutputFormat string
	gatecheckConfig    *gatecheck.Config
}

var RuntimeConfig = metaConfig{
	BundleTag: configkit.MetaField{
		FieldName:    "BundleTag",
		EnvKey:       "GATECHECK_BUNDLE_TAG",
		DefaultValue: "",
		FlagValueP:   new([]string),
		EnvToValueFunc: func(s string) any {
			return strings.Split(s, ",")
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "file properties for metadata",
			metadataFieldType:       "string",
			metadataActionInputName: "bundle_tag",
		},
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*[]string)
			usage := f.Metadata[metadataFlagUsage]
			cmd.Flags().StringSliceVarP(valueP, "tag", "t", []string{}, usage)
		},
	},
	EPSSURL: configkit.MetaField{
		FieldName:    "EPSSURL",
		EnvKey:       "GATECHECK_EPSS_URL",
		DefaultValue: "",
		FlagValueP:   new(string),
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*string)
			usage := f.Metadata[metadataFlagUsage]
			cmd.Flags().StringVar(valueP, "epss-url", "", usage)
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "The url for the FIRST.org EPSS API (\"\" will use FIRST.org official API)",
			metadataFieldType:       "string",
			metadataActionInputName: "epss_url",
		},
	},
	KEVURL: configkit.MetaField{
		FieldName:    "KEVURL",
		EnvKey:       "GATECHECK_KEV_URL",
		DefaultValue: "",
		FlagValueP:   new(string),
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*string)
			usage := f.Metadata[metadataFlagUsage]
			cmd.Flags().StringVar(valueP, "kev-url", "", usage)
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "The url for the CISA KEV API (\"\" will use CISA Official API)",
			metadataFieldType:       "string",
			metadataActionInputName: "kev_url",
		},
	},
	EPSSFilename: configkit.MetaField{
		FieldName:    "EPSSFilename",
		EnvKey:       "GATECHECK_EPSS_FILENAME",
		DefaultValue: "",
		FlagValueP:   new(string),
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*string)
			usage := f.Metadata[metadataFlagUsage]
			cmd.Flags().StringVar(valueP, "epss-filename", "", usage)
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "the filename for a FIRST.org EPSS json file",
			metadataFieldType:       "string",
			metadataActionInputName: "epss_filename",
		},
	},
	Verbose: configkit.MetaField{
		FieldName:    "Verbose",
		EnvKey:       "GATECHECK_VERBOSE",
		DefaultValue: false,
		FlagValueP:   new(bool),
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*bool)
			usage := f.Metadata[metadataFlagUsage]
			cmd.PersistentFlags().BoolVar(valueP, "verbose", false, usage)
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "log level set to debug",
			metadataFieldType:       "bool",
			metadataActionInputName: "verbose",
		},
	},
	Silent: configkit.MetaField{
		FieldName:    "Silent",
		EnvKey:       "GATECHECK_SILENT",
		DefaultValue: false,
		FlagValueP:   new(bool),
		CobraSetupFunc: func(f configkit.MetaField, cmd *cobra.Command) {
			valueP := f.FlagValueP.(*bool)
			usage := f.Metadata[metadataFlagUsage]
			cmd.PersistentFlags().BoolVar(valueP, "silent", false, usage)
		},
		Metadata: map[string]string{
			metadataFlagUsage:       "log level set to only warnings & errors",
			metadataFieldType:       "bool",
			metadataActionInputName: "silent",
		},
	},
}