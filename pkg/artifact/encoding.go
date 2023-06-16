package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// checkFunc is a function that does soft validation to check if a file is formatted correctly
type checkFunc func(v any) error

var ErrEncoding = errors.New("Encoding error")
var ErrDecoders = errors.New("Invalid Decoders")
var ErrInvalidType = errors.New("Invalid Type")
var ErrNilObject = errors.New("Object is nil")
var ErrFailedCheck = errors.New("Invalid file format")

type AsyncDecoder struct {
	bytes.Buffer
	decoders []WriterDecoder
}

func (d *AsyncDecoder) WithDecoders(decs ...WriterDecoder) *AsyncDecoder {
	d.decoders = decs
	return d
}

func (d *AsyncDecoder) Decode(ctx context.Context) (any, error) {
	if len(d.decoders) == 0 {
		return nil, fmt.Errorf("%w: no decoders provided", ErrDecoders)
	}

	objChan := make(chan any)
	doneChan := make(chan struct{})
	var wg sync.WaitGroup
	// Non desctructive reader
	reader := bytes.NewReader(d.Bytes())
	for i := range d.decoders {
		wg.Add(1)
		_, err := reader.WriteTo(d.decoders[i])
		if err != nil {
			return nil, err
		}
		reader.Seek(0, 0)
		go func(decoder WriterDecoder) {
			v, err := decoder.Decode()

			if err != nil {
				wg.Done()
				return
			}

			objChan <- v
		}(d.decoders[i])
	}

	go func(c chan struct{}, wg *sync.WaitGroup) {
		wg.Wait()
		c <- struct{}{}
	}(doneChan, &wg)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	// All decoders finished before one was successful
	case <-doneChan:
		return nil, fmt.Errorf("%w: All decoders failed", ErrInvalidType)
	// One of the decoders were able to successfully decode
	case obj := <-objChan:
		return obj, nil
	}
}

type WriterDecoder interface {
	io.Writer
	Decode() (any, error)
}

type JSONWriterDecoder[T any] struct {
	bytes.Buffer
	checkFunc func(*T) error
}

func NewJSONWriterDecoder[T any](check func(*T) error) *JSONWriterDecoder[T] {
	return &JSONWriterDecoder[T]{
		checkFunc: check,
	}
}

func (d *JSONWriterDecoder[T]) Decode() (any, error) {
	obj := new(T)
	err := json.NewDecoder(d).Decode(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return obj, d.checkFunc(obj)
}
