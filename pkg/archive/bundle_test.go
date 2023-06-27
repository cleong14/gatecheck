package bundle

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	gcc "github.com/gatecheckdev/gatecheck/pkg/artifacts/config"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

func TestBundleEncoding(t *testing.T) {
	bundle := NewBundle()
	bundle.Artifacts["one"] = []byte("content one")
	bundle.Artifacts["two"] = []byte("content two")

	buf := new(bytes.Buffer)
	reader := new(Encoder)
	reader.Encode(bundle)
	reader.WriteTo(buf)

	writer := new(Decoder)
	writer.ReadFrom(buf)
	b, err := writer.Decode()
	if err != nil {
		t.Fatal(err)
	}

	decodeBundle, ok := b.(*Bundle)
	if !ok {
		t.Fatalf("got %T", b)
	}

	if string(decodeBundle.Artifacts["one"]) != "content one" {
		t.Fatalf("want: content one, got: %s", string(decodeBundle.Artifacts["one"]))
	}
	if string(decodeBundle.Artifacts["two"]) != "content two" {
		t.Fatalf("want: content two, got: %s", string(decodeBundle.Artifacts["two"]))
	}
}

func TestBundlePrettyEncoding(t *testing.T) {

	bundle := NewBundle()
	bundle.Artifacts["one"] = []byte("content one")
	bundle.Artifacts["two"] = []byte("content two")

	t.Run("success", func(t *testing.T) {
		buf := new(bytes.Buffer)

		NewPrettyWriter(buf).Encode(bundle)

		t.Log(buf.String())

	})
	t.Run("with-async-decoder-and-required", func(t *testing.T) {
		buf := new(bytes.Buffer)

		decoder := &mockDecoder{useObj: nil, useErr: nil, useFileType: "Mock File"}
		NewPrettyWriter(buf).WithAsyncDecoder(decoder).WithRequiredFileTypes([]string{"Mock File 2"}).Encode(bundle)

		t.Log(buf.String())

	})
}

func TestMockValidator(t *testing.T) {

	objOne := &objA{ValueA: 5, Description: "object a"}
	configOne := &configA{ValueA: 10}
	err := objAValidator().Validate(objOne, configOne)
	t.Log(err)
}

func TestWorkspace(t *testing.T) {
	bundle := NewBundle()

	objOne := &objA{ValueA: 5, Description: "object a"}
	objOneBytes, _ := json.Marshal(objOne)
	bundle.Artifacts["one"] = objOneBytes

	objTwo := &objB{ValueB: 25, Description: "object b"}
	objTwoBytes, _ := json.Marshal(objTwo)
	bundle.Artifacts["two"] = objTwoBytes

	config := &gcc.Config{Version: "1", Artifacts: map[gcc.FieldName]any{"objA": &configA{ValueA: 10}, "objB": &configB{ValueB: 5}}}

	objADecoder := gce.NewJSONWriterDecoder[objA](string(FileTypeObjA), func(oa *objA) error {
		if oa.Description != "object a" {
			return gce.ErrFailedCheck
		}
		return nil
	})
	objBDecoder := gce.NewJSONWriterDecoder[objB](string(FileTypeObjB), func(ob *objB) error {
		if ob.Description != "object b" {
			return gce.ErrFailedCheck
		}
		return nil
	})

	asyncDecoder := new(gce.AsyncDecoder).WithDecoders(objADecoder, objBDecoder)

	validators := []*ArtifactValidator{
		NewArtifactValidator(string(FileTypeObjA), "objA", objAValidator()),
		NewArtifactValidator(string(FileTypeObjB), "objB", objBValidator()),
	}

	validator := NewValidator(validators, asyncDecoder)

	err := validator.Validate(bundle, config)

	t.Log(err)
}

const FileTypeObjA FileType = "Mock Obj A"
const FileTypeObjB FileType = "Mock Obj B"

type objA struct {
	ValueA      int    `json:"valueA"`
	Description string `json:"description"`
}

type configA struct {
	ValueA int `yaml:"valueA"`
}

func objAValidator() AnyValidator {
	return gcv.NewValidator[*objA, *configA](func(oa *objA, ca *configA) error {
		if oa == nil || ca == nil {
			return gcv.ErrInput
		}
		if oa.ValueA > ca.ValueA {
			return gcv.ErrValidation
		}
		return nil
	})
}
func objBValidator() AnyValidator {
	return gcv.NewValidator[*objB, *configB](func(ob *objB, cb *configB) error {
		if ob == nil || cb == nil {
			return gcv.ErrInput
		}
		if ob.ValueB > cb.ValueB {
			return gcv.ErrValidation
		}
		return nil
	})
}

type objB struct {
	ValueB      int    `json:"valueB"`
	Description string `json:"description"`
}

type configB struct {
	ValueB int `yaml:"valueB"`
}

type mockDecoder struct {
	bytes.Buffer
	useObj      any
	useErr      error
	useFileType string
}

func (d *mockDecoder) Decode() (any, error) {
	return d.useObj, d.useErr
}
func (d *mockDecoder) DecodeFrom(_ io.Reader) (any, error) {
	return d.useObj, d.useErr
}

func (d *mockDecoder) FileType() string {
	return d.useFileType
}
