package validate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"testing"
)

func TestNewValidator(t *testing.T) {
	testTable := []struct {
		label     string
		wantErr   error
		useReport any
		useConfig any
	}{
		{label: "success-pass-validation", wantErr: nil, useReport: MockReport{High: 5, Low: 6}, useConfig: MockConfig{High: 10, Low: 10}},
		{label: "success-fail-validation", wantErr: ErrValidation, useReport: MockReport{High: 5, Low: 6}, useConfig: MockConfig{High: 0, Low: 0}},
		{label: "invalid-report", wantErr: ErrValidation, useReport: MockConfig{High: 5, Low: 6}, useConfig: MockConfig{High: 0, Low: 0}},
		{label: "invalid-config", wantErr: ErrValidation, useReport: MockReport{High: 5, Low: 6}, useConfig: MockReport{High: 0, Low: 0}},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			validator := NewMockValidator()

			err := validator.Validate(testCase.useReport, testCase.useConfig)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
	}
}

func TestNewValidatorWithDecode(t *testing.T) {
	testTable := []struct {
		label            string
		wantErr          error
		useReportDecoder WriterDecoder
		useConfigDecoder WriterDecoder
		useReport        *MockReport
		useConfig        *MockConfig
	}{
		{label: "success", wantErr: nil, useReportDecoder: &mockWriterDecoder[MockReport]{}, useConfigDecoder: &mockWriterDecoder[MockConfig]{},
			useReport: &MockReport{High: 5, Low: 6}, useConfig: &MockConfig{High: 10, Low: 10},
		},
		{label: "invalid-report", wantErr: ErrValidation, useReportDecoder: &mockWriterDecoder[MockConfig]{}, useConfigDecoder: &mockWriterDecoder[MockConfig]{},
			useReport: &MockReport{High: 5, Low: 6}, useConfig: &MockConfig{High: 10, Low: 10},
		},
		{label: "invalid-config", wantErr: ErrValidation, useReportDecoder: &mockWriterDecoder[MockReport]{}, useConfigDecoder: &mockWriterDecoder[MockReport]{},
			useReport: &MockReport{High: 5, Low: 6}, useConfig: &MockConfig{High: 10, Low: 10},
		},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			validator := NewMockValidator().WithDecoders(testCase.useReportDecoder, testCase.useConfigDecoder)

			err := validator.ValidateFrom(jsonReader(testCase.useReport), jsonReader(testCase.useConfig))
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
	}
}

func jsonReader(v any) io.Reader {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(v)
	return buf
}

type mockWriterDecoder[T any] struct {
	bytes.Buffer
}

func (m *mockWriterDecoder[T]) Decode() (any, error) {
	obj := new(T)
	err := json.NewDecoder(m).Decode(obj)
	return obj, err
}

func NewMockValidator() *Validator[MockReport, MockConfig] {
	return NewValidator[MockReport, MockConfig](mockValidate)
}

type MockReport struct {
	High int
	Low  int
}

type MockConfig struct {
	High int
	Low  int
}

func mockValidate(r MockReport, c MockConfig) error {
	if r.High > c.High || r.Low > c.Low {
		return ErrValidation
	}
	return nil
}
