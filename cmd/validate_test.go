package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	gosemgrep "github.com/BacchusJackson/go-semgrep"
	"github.com/anchore/grype/grype/presenter/models"
	gca "github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"gopkg.in/yaml.v3"
)

func TestGrype(t *testing.T) {
	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})
	grypeFilename := writeTempAny(&grypeReport, t)

	obj, err := gce.NewAsyncDecoder(grype.NewReportDecoder()).DecodeFrom(MustOpen(grypeFilename, t.Fatal))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(obj)

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

	bundle := gca.NewBundle()
	bundle.Artifacts["grype-report.json"] = MustRead(grypeFilename, t)
	bundle.Artifacts["semgrep-report.json"] = MustRead(semgrepFilename, t)
	bundle.Artifacts["gitleaks-report.json"] = MustRead(gitleaksFilename, t)

	bundleFilename := path.Join(t.TempDir(), "bundle.gatecheck")	
	_ = gca.NewEncoder(MustCreate(bundleFilename, t)).Encode(bundle)

	newAsyncDecoder := func() AsyncDecoder {
		return gce.NewAsyncDecoder(
			grype.NewReportDecoder(),
			semgrep.NewReportDecoder(),
			gitleaks.NewReportDecoder(),
			gca.NewDecoder(),
		)
	}

	testTable := []struct {
		label      string
		wantErr    error
		reportFunc func(*testing.T) string
		configFunc func(*testing.T) string
	}{
		{label: "bad-object-file", wantErr: ErrorFileAccess, reportFunc: fileWithBadPermissions, configFunc: fileWithBadPermissions},
		{label: "bad-config-file", wantErr: ErrorFileAccess, reportFunc: fileFunc(grypeTestReport), configFunc: fileWithBadPermissions},
		{label: "grype-pass", wantErr: nil, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configPassFilename)},
		{label: "grype-fail", wantErr: ErrorValidation, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configFailFilename)},
		{label: "semgrep-pass", wantErr: nil, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configPassFilename)},
		{label: "semgrep-fail", wantErr: ErrorValidation, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configFailFilename)},
		{label: "gitleaks-pass", wantErr: nil, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configPassFilename)},
		{label: "gitleaks-fail", wantErr: ErrorValidation, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configFailFilename)},
		{label: "bundle-pass", wantErr: nil, reportFunc: fileFunc(bundleFilename), configFunc: fileFunc(configPassFilename)},
		{label: "bundle-fail", wantErr: ErrorValidation, reportFunc: fileFunc(bundleFilename), configFunc: fileFunc(configFailFilename)},
	}

	for _, testCase := range testTable {
		// commandString := fmt.Sprintf("validate -c %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		t.Run(testCase.label, func(t *testing.T) {
			report := testCase.reportFunc(t)
			config := testCase.configFunc(t)
			commandString := fmt.Sprintf("validate -c %s %s", config, report)
			output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: newAsyncDecoder})
			t.Log(output)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want %v got %v", testCase.wantErr, err)
			}

		})

	}
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

func MustCreate(filename string, t *testing.T) *os.File {
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func MustRead(filename string, t *testing.T) []byte {
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// func TestNewValidateCmd(t *testing.T) {
// 	t.Run("bad-config", func(t *testing.T) {
// 		commandString := fmt.Sprintf("validate -c %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
// 		output, err := Execute(commandString, CLIConfig{})
//
// 		if errors.Is(err, ErrorFileAccess) != true {
// 			t.Fatal(err)
// 		}
//
// 		t.Log(output)
// 	})
//
// 	t.Run("bad-config-decode", func(t *testing.T) {
// 		commandString := fmt.Sprintf("validate -c %s %s", fileWithBadJSON(t), fileWithBadPermissions(t))
// 		output, err := Execute(commandString, CLIConfig{})
//
// 		if errors.Is(err, ErrorEncoding) != true {
// 			t.Fatal(err)
// 		}
//
// 		t.Log(output)
// 	})
//
// 	t.Run("bad-target", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
// 		commandString := fmt.Sprintf("validate -c %s %s", configFile, fileWithBadPermissions(t))
// 		output, err := Execute(commandString, CLIConfig{})
//
// 		if errors.Is(err, ErrorFileAccess) != true {
// 			t.Fatal(err)
// 		}
//
// 		t.Log(output)
// 	})
//
// 	t.Run("validation-error", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
// 		commandString := fmt.Sprintf("validate -c %s %s", configFile, gitleaksTestReport)
// 		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorValidation) != true {
// 			t.Fatal(err)
// 		}
//
// 		t.Run("audit", func(t *testing.T) {
// 			commandString := fmt.Sprintf("validate --audit -c %s %s", configFile, gitleaksTestReport)
// 			_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 			if err != nil {
// 				t.Fatal(err)
// 			}
// 		})
// 	})
//
// 	t.Run("success-with-kev", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		config := artifact.NewConfig()
// 		config.Grype.Critical = 0
// 		_ = yaml.NewEncoder(f).Encode(config)
// 		commandString := fmt.Sprintf("validate -k %s -c %s %s",
// 			kevTestFile, configFile, grypeTestReport)
// 		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorValidation) != true {
// 			t.Log(output)
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("with-kev-audit", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		config := artifact.NewConfig()
// 		config.Grype.Critical = 0
// 		_ = yaml.NewEncoder(f).Encode(config)
// 		commandString := fmt.Sprintf("validate --audit -k %s -c %s %s",
// 			kevTestFile, configFile, grypeTestReport)
// 		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if err != nil {
// 			t.Log(output)
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("with-kev-found-vulnerability", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		config := artifact.NewConfig()
// 		config.Grype.Critical = 0
// 		_ = yaml.NewEncoder(f).Encode(config)
//
// 		var grypeScan artifact.GrypeScanReport
// 		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
// 		grypeScan.Matches = append(grypeScan.Matches,
// 			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
// 		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
// 		f, _ = os.Create(tempGrypeScanFile)
// 		_ = json.NewEncoder(f).Encode(grypeScan)
//
// 		kev := artifact.KEVCatalog{Vulnerabilities: []artifact.KEVCatalogVulnerability{
// 			{CveID: "A"},
// 		}}
// 		tempKEVScanFile := path.Join(t.TempDir(), "new-kev.json")
// 		f, _ = os.Create(tempKEVScanFile)
// 		_ = json.NewEncoder(f).Encode(kev)
//
// 		commandString := fmt.Sprintf("validate -k %s -c %s %s",
// 			tempKEVScanFile, configFile, tempGrypeScanFile)
// 		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorValidation) != true {
// 			t.Log(output)
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("kev-file-access", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
// 		commandString := fmt.Sprintf("validate -k %s -c %s %s",
// 			fileWithBadPermissions(t), configFile, gitleaksTestReport)
// 		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorFileAccess) != true {
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("kev-bad-decode", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
// 		commandString := fmt.Sprintf("validate -k %s -c %s %s", fileWithBadJSON(t), configFile, gitleaksTestReport)
// 		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorEncoding) != true {
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("kev-unsupported", func(t *testing.T) {
// 		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
// 		f, _ := os.Create(configFile)
// 		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
// 		commandString := fmt.Sprintf("validate -k %s -c %s %s", kevTestFile, configFile, gitleaksTestReport)
// 		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})
//
// 		if errors.Is(err, ErrorEncoding) != true {
// 			t.Fatal(err)
// 		}
// 	})
// }
//
//
// func TestParseAndValidate(t *testing.T) {
// 	const timeout = time.Second * 3
// 	t.Run("timeout", func(t *testing.T) {
// 		b := make([]byte, 10_000)
// 		rand.Read(b)
// 		err := ParseAndValidate(bytes.NewBuffer(b), *artifact.NewConfig(), time.Nanosecond)
// 		if errors.Is(err, context.Canceled) != true {
// 			t.Fatal(err)
// 		}
// 	})
// 	t.Run("semgrep", func(t *testing.T) {
// 		config := artifact.NewConfig()
// 		config.Semgrep = nil
// 		err := ParseAndValidate(MustOpen(semgrepTestReport, t.Fatal), *config, timeout)
// 		if err == nil {
// 			t.Fatal("Expected error for missing configuration")
// 		}
// 		config.Semgrep = artifact.NewConfig().Semgrep
// 		err = ParseAndValidate(MustOpen(semgrepTestReport, t.Fatal), *config, timeout)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 	})
//
// 	t.Run("grype", func(t *testing.T) {
// 		config := artifact.NewConfig()
// 		config.Grype = nil
// 		err := ParseAndValidate(MustOpen(grypeTestReport, t.Fatal), *config, timeout)
// 		if err == nil {
// 			t.Fatal("Expected error for missing configuration")
// 		}
// 		config.Grype = artifact.NewConfig().Grype
// 		err = ParseAndValidate(MustOpen(grypeTestReport, t.Fatal), *config, timeout)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 	})
// 	t.Run("gitleaks", func(t *testing.T) {
// 		config := artifact.NewConfig()
// 		config.Gitleaks = nil
// 		err := ParseAndValidate(MustOpen(gitleaksTestReport, t.Fatal), *config, timeout)
// 		if err == nil {
// 			t.Fatal("Expected error for missing configuration")
// 		}
//
// 		config.Gitleaks = artifact.NewConfig().Gitleaks
// 		config.Gitleaks.SecretsAllowed = true
// 		err = ParseAndValidate(MustOpen(gitleaksTestReport, t.Fatal), *config, timeout)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 	})
// 	t.Run("unsupported", func(t *testing.T) {
// 		b := make([]byte, 10_000)
// 		rand.Read(b)
// 		err := ParseAndValidate(bytes.NewBuffer(b), *artifact.NewConfig(), timeout)
// 		if err == nil {
// 			t.Fatal("Expected error for missing configuration")
// 		}
// 	})
//
// }
//
// func TestParseAndValidate_bundle(t *testing.T) {
//
// 	grypeArtifact, _ := artifact.NewArtifact("grype", MustOpen(grypeTestReport, t.Fatal))
// 	semgrepArtifact, _ := artifact.NewArtifact("semgrep", MustOpen(semgrepTestReport, t.Fatal))
// 	gitleaksArtifact, _ := artifact.NewArtifact("gitleaks", MustOpen(gitleaksTestReport, t.Fatal))
//
// 	bundle := artifact.NewBundle()
// 	_ = bundle.Add(grypeArtifact, semgrepArtifact, gitleaksArtifact)
//
// 	t.Run("fail-validation", func(t *testing.T) {
//
// 		config := artifact.NewConfig()
// 		config.Grype.Critical = 0
// 		config.Semgrep.Error = 0
// 		config.Gitleaks.SecretsAllowed = false
//
// 		buf := new(bytes.Buffer)
// 		_ = artifact.NewBundleEncoder(buf).Encode(bundle)
// 		err := ParseAndValidate(buf, *config, time.Second*3)
//
// 		if err == nil {
// 			t.Fatal("expected error for failed validation")
// 		}
//
// 		t.Log(err)
// 	})
//
// 	t.Run("pass-validation", func(t *testing.T) {
//
// 		config := artifact.NewConfig()
// 		config.Gitleaks.SecretsAllowed = true
//
// 		buf := new(bytes.Buffer)
// 		_ = artifact.NewBundleEncoder(buf).Encode(bundle)
// 		err := ParseAndValidate(buf, *config, time.Second*3)
//
// 		if err != nil {
// 			t.Fatal(err)
// 		}
//
// 		t.Log(err)
// 	})
//
// }
//
