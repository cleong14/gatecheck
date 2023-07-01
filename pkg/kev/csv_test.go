package kev

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestCSVDecoder(t *testing.T) {
	testTable := []struct {
		label   string
		wantErr error
		reader  io.Reader
	}{
		{label: "success", wantErr: nil, reader: MustOpen("../../test/known_exploited_vulnerabilities.csv", t)},
		{label: "bad-reader", wantErr: gce.ErrIO, reader: badReader{}},
		{label: "bad-header", wantErr: gce.ErrEncoding, reader: strings.NewReader("a,b,c,d")},
	}

	for _, testCase := range testTable {
		obj, err := NewCSVDecoder().DecodeFrom(testCase.reader)
		if !errors.Is(err, testCase.wantErr) {
			t.Fatalf("want: %v got: %v", testCase.wantErr, err)
		}
		if err == nil {
			t.Logf("%+v", obj.(*Catalog).Vulnerabilities[:10])
		}

	}
}

type badReader struct{}

func (r badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("Mock Error")
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
