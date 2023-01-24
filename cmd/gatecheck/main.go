package main

import (
	"errors"
	"github.com/gatecheckdev/gatecheck/cmd"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"net/http"
	"os"
	"time"
)

const ExitSystemFail int = -1
const ExitOk int = 0
const ExitFileAccessFail int = 2
const ExitValidationFail = 1

func main() {
	dojoKey := os.Getenv("GATECHECK_DD_API_KEY")
	dojoURL := os.Getenv("GATECHECK_DD_API_URL")

	ddEngagement := defectdojo.EngagementQuery{
		ProductTypeName: os.Getenv("GATECHECK_DD_PRODUCT_TYPE"),
		ProductName:     os.Getenv("GATECHECK_DD_PRODUCT"),
		Name:            os.Getenv("GATECHECK_DD_ENGAGEMENT"),
		Duration:        time.Hour * 48,
		BranchTag:       os.Getenv("GATECHECK_DD_BRANCH_TAG"),
		SourceURL:       os.Getenv("GATECHECK_DD_SOURCE_URL"),
		CommitHash:      os.Getenv("GATECHECK_DD_COMMIT_HASH"),
	}

	dojoService := defectdojo.NewService(http.DefaultClient, dojoKey, dojoURL)
	epssService := epss.NewEPSSService(http.DefaultClient, "https://api.first.org/data/v1/epss")

	var pipedFile *os.File
	if PipeInput() {
		pipedFile = os.Stdin
	}

	command := cmd.NewRootCommand(cmd.CLIConfig{
		AutoDecoderTimeout: 5 * time.Second,
		DDExportTimeout:    5 * time.Minute,
		Version:            "0.0.8",
		EPSSService:        epssService,
		DDExportService:    &dojoService,
		DDEngagement:       ddEngagement,
		PipedInput:         pipedFile,
	})

	command.SilenceUsage = true
	err := command.Execute()

	if errors.Is(err, cmd.ErrorFileAccess) {
		command.PrintErrln(err)
		os.Exit(ExitFileAccessFail)
	}

	if errors.Is(err, cmd.ErrorValidation) {
		os.Exit(ExitValidationFail)
	}

	if err != nil {
		command.PrintErrln(err)
		os.Exit(ExitSystemFail)
	}

	os.Exit(ExitOk)
}

// PipeInput checks for input from a Linux Pipe ex. 'cat grype-report.json | gatecheck print'
func PipeInput() bool {
	fileInfo, _ := os.Stdin.Stat()
	return fileInfo.Mode()&os.ModeCharDevice == 0
}