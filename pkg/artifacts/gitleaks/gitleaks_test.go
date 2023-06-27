package gitleaks

import (
	"errors"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestCheckConfig(t *testing.T) {
	if err := checkConfig(nil); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatal("want: failed check error got:", err)
	}
	if err := checkConfig(&OuterConfig{Gitleaks: nil}); !errors.Is(err, gce.ErrFailedCheck) {
		t.Fatal("want: failed check error got:", err)
	}
	config := &Config{Required: true, SecretsAllowed: false}
	if err := checkConfig(&OuterConfig{Gitleaks: config}); err != nil {
		t.Fatalf("want: nil got: %v", err)
	}
}
