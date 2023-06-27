package encoding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestNewJSONWriterDecoder(t *testing.T) {
	var newPersonDecoder = func() *JSONWriterDecoder[mockPerson] {
		return NewJSONWriterDecoder[mockPerson]("Mock Person", func(mp *mockPerson) error {
			if mp.Age < 10 || mp.Age > 150 {
				return fmt.Errorf("%w: mock check error", ErrFailedCheck)
			}
			return nil
		})
	}
	t.Log(newPersonDecoder().FileType())

	goodBuf := new(bytes.Buffer)
	badBuf := new(bytes.Buffer)

	_ = json.NewEncoder(goodBuf).Encode(&mockPerson{FirstName: "Tony", LastName: "Stark", Age: 53})

	t.Log(string(goodBuf.Bytes()))

	badBuf.ReadFrom(strings.NewReader("}}}"))

	testTable := []struct {
		label         string
		useReader     io.Reader
		wantDecodeErr error
	}{
		{label: "success", useReader: goodBuf, wantDecodeErr: nil},
		{label: "bad-decode", useReader: badBuf, wantDecodeErr: ErrEncoding},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			decoder := newPersonDecoder()
			_, err := decoder.ReadFrom(testCase.useReader)

			a, err := decoder.Decode()
			if !errors.Is(err, testCase.wantDecodeErr) {
				t.Fatalf("want: %v got: %v", testCase.wantDecodeErr, err)
			}
			t.Log(a)
		})
	}
}

func TestNewYAMLWriterDecoder(t *testing.T) {
	var newPersonDecoder = func() *YAMLWriterDecoder[mockPerson] {
		return NewYAMLWriterDecoder[mockPerson]("Mock Person", func(mp *mockPerson) error {
			if mp.Age < 10 || mp.Age > 150 {
				return fmt.Errorf("%w: mock check error", ErrFailedCheck)
			}
			return nil
		})
	}

	t.Log(newPersonDecoder().FileType())
	goodBuf := new(bytes.Buffer)
	badBuf := new(bytes.Buffer)

	_ = yaml.NewEncoder(goodBuf).Encode(&mockPerson{FirstName: "Tony", LastName: "Stark", Age: 53})

	t.Log(string(goodBuf.Bytes()))

	badBuf.ReadFrom(strings.NewReader("}}}"))

	testTable := []struct {
		label         string
		useReader     io.Reader
		wantDecodeErr error
	}{
		{label: "success", useReader: goodBuf, wantDecodeErr: nil},
		{label: "bad-decode", useReader: badBuf, wantDecodeErr: ErrEncoding},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			decoder := newPersonDecoder()
			_, err := decoder.ReadFrom(testCase.useReader)

			a, err := decoder.Decode()
			if !errors.Is(err, testCase.wantDecodeErr) {
				t.Fatalf("want: %v got: %v", testCase.wantDecodeErr, err)
			}
			t.Log(a)
		})
	}

}

type mockPerson struct {
	FirstName string `json:"firstName" yaml:"firstName"`
	LastName  string `json:"lastName" yaml:"lastName"`
	Age       int    `json:"age" yaml:"age"`
}
