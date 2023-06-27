package fs

import (
	"errors"
	"io"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
)

var ErrDecode = errors.New("decoding error")

func ReadFile(filename string, w io.Writer) (int64, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	return io.Copy(w, f)
}

func ReadDecodeFile(filename string, w artifact.WriterDecoder) (any, error) {
	if _, err := ReadFile(filename, w); err != nil {
		return nil, err
	}
	return w.Decode()
}
