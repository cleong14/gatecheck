package artifact

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewBundle(t *testing.T) {
	t.Run("without-config", func(t *testing.T) {

		art, _ := NewArtifact("some-artifact.txt", strings.NewReader("some content"))
		bundle := NewBundle(art)
		v, ok := bundle.Artifacts["some-artifact.txt"]
		if !ok {
			t.Fatalf("want artifact in bundle, got %+v", bundle)
		}
		if v.Type != TypeGeneric {
			t.Fatal("want generic, got", v.Type)
		}
		if string(v.Content) != "some content" {
			t.Fatalf("want 'some-content' got '%s'", string(v.Content))
		}
	})

	t.Run("with-config", func(t *testing.T) {
		art1, _ := NewArtifact("some-artifact.txt", strings.NewReader("some content"))
		configReader, _ := NewConfigReader(NewConfig())
		art2, _ := NewArtifact("gatecheck.yaml", configReader)
		if art2.Type != TypeGatecheckConfig {
			t.Fatalf("want %s, got %s", string(TypeGatecheckConfig), art2.Type)
		}
		bundle := NewBundle(art1, art2)

		if bundle.config == nil {
			t.Fatal("want config, got nil")
		}
	})

}

func TestBundleReader(t *testing.T) {
	grypeArtifact, _ := NewArtifact("grype-report.json", bytes.NewReader(MustReadFile("../../test/grype-report.json", t.Fatal)))
	semgrepArtifact, _ := NewArtifact("semgrep-report.json", bytes.NewReader(MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)))
	config := NewConfig()
	config.Grype.Required = true
	configReader, _ := NewConfigReader(config)
	configArtifact, _ := NewArtifact("gatecheck.yaml", configReader)
	bundle := NewBundle(grypeArtifact, semgrepArtifact, configArtifact)

	tempBuffer := new(bytes.Buffer)
	if _, err := NewBundleReader(bundle).WriteTo(tempBuffer); err != nil {
		t.Fatal(err)
	}

	writer := new(BundleWriter)
	if _, err := writer.ReadFrom(tempBuffer); err != nil {
		t.Fatal(err)
	}
	v, err := writer.Decode()
	if err != nil {
		t.Fatal(err)
	}

	decodeBundle, ok := v.(*Bundle)
	if !ok {
		t.Fatal("decoded bundle is not a *Bundle")
	}

	if _, ok := decodeBundle.Artifacts["grype-report.json"]; !ok {
		t.Fatalf("Want decoded bundle, got %+v", decodeBundle)
	}

	wantDigest := bundle.Artifacts["grype-report.json"].DigestString()
	gotDigest := decodeBundle.Artifacts["grype-report.json"].DigestString()

	if gotDigest != wantDigest {
		t.Fatalf("want: %s got: %s", wantDigest, gotDigest)
	}

	if bundle.config.Grype.Required != true {
		t.Fatalf("want: grype config Required, got: %+v", &bundle.config.Grype)
	}

	t.Logf("Config: %+v", bundle.config)
	t.Logf("Grype Config: %+v", bundle.config.Grype)
	t.Log(bundle, "\n")
	t.Log(decodeBundle)
}

