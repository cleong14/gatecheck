package artifact

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestValidator_Validate(t *testing.T) {

	secretsAllowedConfig := NewConfig()
	secretsAllowedConfig.Gitleaks.SecretsAllowed = true
	grypeArtifact, _ := NewArtifact("grype report", bytes.NewReader(MustReadFile("../../test/grype-report.json", t.Fatal)))
	semgrepArtifact, _ := NewArtifact("semgrep report", bytes.NewReader(MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)))
	gitleaksArtifact, _ := NewArtifact("gitleaks report", bytes.NewReader(MustReadFile("../../test/gitleaks-report.json", t.Fatal)))
	cyclonedxArtifact, _ := NewArtifact("cyclonedx report", bytes.NewReader(MustReadFile("../../test/cyclonedx-grype-sbom.json", t.Fatal)))
	bundle := NewBundle(grypeArtifact, semgrepArtifact, gitleaksArtifact, cyclonedxArtifact)

	var newBundleReader = func() io.Reader {
		br, _ := NewBundleReader(bundle)
		return br
	}

	bundleFailConfig := NewConfig()
	bundleFailConfig.Grype.High = 0

	testTable := []struct {
		label     string
		wantErr   error
		useConfig Config
		useReader io.Reader
	}{
		{label: "grype-success", wantErr: nil, useConfig: *NewConfig(), useReader: bytes.NewReader(grypeArtifact.ContentBytes())},
		{label: "semgrep-success", wantErr: nil, useConfig: *NewConfig(), useReader: bytes.NewReader(semgrepArtifact.ContentBytes())},
		{label: "gitleaks-success", wantErr: nil, useConfig: *secretsAllowedConfig, useReader: bytes.NewReader(gitleaksArtifact.ContentBytes())},
		{label: "cyclonedx-success", wantErr: nil, useConfig: *NewConfig(), useReader: bytes.NewReader(cyclonedxArtifact.ContentBytes())},
		{label: "bundle-success", wantErr: nil, useConfig: *secretsAllowedConfig, useReader: newBundleReader()},
		{label: "bundle-failure", wantErr: ErrValidation, useConfig: *bundleFailConfig, useReader: newBundleReader()},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			validator := NewValidator(testCase.useConfig)
			_, _ = validator.ReadFrom(testCase.useReader)
			if err := validator.Validate(); !errors.Is(err, testCase.wantErr) {
				t.Fatal(err)
			}
		})
	}
}
