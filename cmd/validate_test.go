package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path"
	"testing"
	"time"

	gosemgrep "github.com/BacchusJackson/go-semgrep"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	"gopkg.in/yaml.v3"
)

func TestKEVValidation(t *testing.T) {

	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})

	t.Run("success-pass-download", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			catalog := &kev.Catalog{Title: "Mock Catalog", CatalogVersion: "Mock Version", DateReleased: time.Now(), Count: 1,
				Vulnerabilities: []kev.Vulnerability{{CveID: "abc-123"}}}
			_ = json.NewEncoder(w).Encode(catalog)
		}))

		commandString := fmt.Sprintf("validate --fetch-kev -c %s %s", configFilename, reportFilename)
		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, Client: mockServer.Client(), KEVDownloadURL: mockServer.URL})
		t.Log(output)

		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want %v got %v", ErrorValidation, err)
		}

	})

	t.Run("download-api-failure", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		mockServer.Close()

		commandString := fmt.Sprintf("validate --fetch-kev -c %s %s", configFilename, reportFilename)

		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, Client: mockServer.Client(), KEVDownloadURL: mockServer.URL})
		t.Log(output)

		if !errors.Is(err, ErrorAPI) {
			t.Fatalf("want %v got %v", ErrorAPI, err)
		}

	})

	t.Run("success-fail", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		kevFilenameFail := writeTempAny(&kev.Catalog{
			Title: "Mock Catalog", CatalogVersion: "Mock Version", DateReleased: time.Now(),
			Count: 1, Vulnerabilities: []kev.Vulnerability{{CveID: "abc-123"}},
		}, t)
		commandString := fmt.Sprintf("validate -k %s -c %s %s", kevFilenameFail, configFilename, reportFilename)
		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
		t.Log(output)

		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want %v got %v", ErrorValidation, err)
		}
	})

	t.Run("success-pass", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)
		kevFilenamePass := writeTempAny(&kev.Catalog{
			Title:           "Mock Catalog",
			CatalogVersion:  "Mock Version",
			DateReleased:    time.Now(),
			Count:           1,
			Vulnerabilities: []kev.Vulnerability{{CveID: "def-345"}},
		}, t)

		commandString := fmt.Sprintf("validate -k %s -c %s %s", kevFilenamePass, configFilename, reportFilename)
		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
		t.Log(output)

		if err != nil {
			t.Fatalf("want %v got %v", nil, err)
		}
	})

	reportFilename := writeTempAny(&grypeReport, t)
	configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1},
		"semgrep": semgrep.Config{Error: -1, Info: -1, Warning: -1}}, t)

	t.Run("kev-flag-no-grype-file", func(t *testing.T) {
		semgrepReport := semgrep.ScanReport{Errors: make([]gosemgrep.CliError, 0)}
		semgrepReport.Paths.Scanned = make([]string, 0)
		semgrepReport.Results = append(semgrepReport.Results, gosemgrep.CliMatch{Extra: gosemgrep.CliMatchExtra{Severity: "ERROR", Metadata: gosemgrep.CliMatchExtra{Severity: "ERROR"}}})

		semgrepFilename := writeTempAny(&semgrepReport, t)

		commandString := fmt.Sprintf("validate --fetch-kev -c %s %s", configFilename, semgrepFilename)

		_, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})

		if err != nil {
			t.Fatalf("want %v got %v", nil, err)
		}

	})

	t.Run("kev-bad-file", func(t *testing.T) {
		commandString := fmt.Sprintf("validate -k %s -c %s %s", fileWithBadPermissions(t), configFilename, reportFilename)
		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
		t.Log(output)

		if !errors.Is(err, ErrorFileAccess) {
			t.Fatalf("want %v got %v", ErrorFileAccess, err)
		}
	})
	t.Run("kev-bad-encoding", func(t *testing.T) {
		commandString := fmt.Sprintf("validate -k %s -c %s %s", fileWithBadJSON(t), configFilename, reportFilename)
		output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
		t.Log(output)

		if !errors.Is(err, ErrorEncoding) {
			t.Fatalf("want %v got %v", ErrorEncoding, err)
		}
	})

}

func TestAuditFlag(t *testing.T) {
	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})
	reportFilename := writeTempAny(&grypeReport, t)
	configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

	commandString := fmt.Sprintf("validate -c %s %s", configFilename, reportFilename)
	output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
	t.Log(output)

	if !errors.Is(err, ErrorValidation) {
		t.Fatalf("want %v got %v", ErrorValidation, err)
	}

	commandString = fmt.Sprintf("validate --audit -c %s %s", configFilename, reportFilename)
	output, err = Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
	t.Log(output)

	if err != nil {
		t.Fatalf("want %v got %v", nil, err)
	}

}

func TestValidateCmd(t *testing.T) {
	fileFunc := func(input string) func(t *testing.T) string {
		return func(t *testing.T) string { return input }
	}

	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})
	grypeConfigPass := grype.Config{Critical: -1, High: -1, Low: -1, Medium: -1, Unknown: -1}
	grypeConfigFail := grype.Config{Critical: 0, High: -1, Low: -1, Medium: -1, Unknown: -1}

	semgrepReport := semgrep.ScanReport{Errors: make([]gosemgrep.CliError, 0)}
	semgrepReport.Paths.Scanned = make([]string, 0)
	semgrepReport.Results = append(semgrepReport.Results, gosemgrep.CliMatch{Extra: gosemgrep.CliMatchExtra{Severity: "ERROR", Metadata: gosemgrep.CliMatchExtra{Severity: "ERROR"}}})

	semgrepConfigPass := semgrep.Config{Info: -1, Warning: -1, Error: -1}
	semgrepConfigFail := semgrep.Config{Info: -1, Warning: -1, Error: 0}

	gitleaksReport := gitleaks.ScanReport{
		gitleaks.Finding{Description: "Some desc", Secret: "Some secret", RuleID: "abc-123"},
		gitleaks.Finding{Description: "Some desc 2", Secret: "Some secret 2", RuleID: "abc-124"},
	}

	gitleaksConfigPass := gitleaks.Config{SecretsAllowed: true}
	gitleaksConfigFail := gitleaks.Config{SecretsAllowed: false}

	semgrepFilename := writeTempAny(&semgrepReport, t)
	grypeFilename := writeTempAny(&grypeReport, t)
	gitleaksFilename := writeTempAny(&gitleaksReport, t)

	configPass := map[string]any{grype.ConfigFieldName: grypeConfigPass, semgrep.ConfigFieldName: semgrepConfigPass, gitleaks.ConfigFieldName: gitleaksConfigPass}
	configFail := map[string]any{grype.ConfigFieldName: grypeConfigFail, semgrep.ConfigFieldName: semgrepConfigFail, gitleaks.ConfigFieldName: gitleaksConfigFail}

	configPassFilename := writeTempConfig(configPass, t)
	configFailFilename := writeTempConfig(configFail, t)

	testTable := []struct {
		label      string
		wantErr    error
		reportFunc func(*testing.T) string
		configFunc func(*testing.T) string
	}{
		{label: "grype-pass", wantErr: nil, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configPassFilename)},
		{label: "grype-fail", wantErr: ErrorValidation, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configFailFilename)},
		{label: "semgrep-pass", wantErr: nil, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configPassFilename)},
		{label: "semgrep-fail", wantErr: ErrorValidation, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configFailFilename)},
		{label: "gitleaks-pass", wantErr: nil, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configPassFilename)},
		{label: "gitleaks-fail", wantErr: ErrorValidation, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configFailFilename)},
		{label: "bad-object-file", wantErr: ErrorFileAccess, reportFunc: fileWithBadPermissions, configFunc: fileWithBadPermissions},
		{label: "bad-config-file", wantErr: ErrorFileAccess, reportFunc: fileFunc(grypeTestReport), configFunc: fileWithBadPermissions},
		{label: "decode-error", wantErr: ErrorEncoding, reportFunc: fileWithBadJSON, configFunc: fileFunc(configPassFilename)},
	}

	for _, testCase := range testTable {
		// commandString := fmt.Sprintf("validate -c %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		t.Run(testCase.label, func(t *testing.T) {
			report := testCase.reportFunc(t)
			config := testCase.configFunc(t)
			commandString := fmt.Sprintf("validate -c %s %s", config, report)
			output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
			t.Log(output)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want %v got %v", testCase.wantErr, err)
			}

		})

	}
}

func NewAsyncDecoder() AsyncDecoder {
	return gce.NewAsyncDecoder(
		grype.NewReportDecoder(),
		semgrep.NewReportDecoder(),
		gitleaks.NewReportDecoder(),
	)
}

func writeTempAny(v any, t *testing.T) string {
	filename := path.Join(t.TempDir(), "some-report.json")
	f := MustCreate(filename, t)
	_ = json.NewEncoder(f).Encode(v)
	_ = f.Close()
	return filename
}

func writeTempConfig(configMap map[string]any, t *testing.T) string {
	filename := path.Join(t.TempDir(), "config-pass.yaml")
	configFile := MustCreate(filename, t)
	_ = yaml.NewEncoder(configFile).Encode(configMap)
	_ = configFile.Close()
	return filename
}
