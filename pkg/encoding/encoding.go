package encoding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

var ErrEncoding = errors.New("encoding error")
var ErrIO = errors.New("input/output error")
var ErrFailedCheck = errors.New("object field check failed")

type JSONWriterDecoder[T any] struct {
	bytes.Buffer
	checkFunc func(*T) error
	fileType  string
}

func NewJSONWriterDecoder[T any](fileType string, check func(*T) error) *JSONWriterDecoder[T] {
	return &JSONWriterDecoder[T]{
		checkFunc: check,
		fileType:  fileType,
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
func (d *JSONWriterDecoder[T]) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

func (d *JSONWriterDecoder[T]) FileType() string {
	return d.fileType
}

type MapDecoder[T any] struct {
	bytes.Buffer
	declaredReader io.Reader
	fileType       string
	fieldName      string
}

func (d *MapDecoder[T]) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

func (d *MapDecoder[T]) Decode() (any, error) {
	m := make(map[string]any)
	err := yaml.NewDecoder(d).Decode(m)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	subM, ok := m[d.fieldName]
	if !ok {
		return nil, fmt.Errorf("%w: field name '%s' not found", ErrEncoding, d.fieldName)
	}

	// Can't error, verified through decoding
	_ = yaml.NewEncoder(d).Encode(subM)
	obj := new(T)
	err = yaml.NewDecoder(d).Decode(obj)
	return *obj, err
}

func (d *MapDecoder[_]) FileType() string {
	return d.fileType
}
func (d *MapDecoder[_]) FieldName() string {
	return d.fieldName
}

func NewMapDecoder[T any](fileType string, fieldName string) *MapDecoder[T] {
	return &MapDecoder[T]{fileType: fileType, fieldName: fieldName}
}

type YAMLWriterDecoder[T any] struct {
	bytes.Buffer
	checkFunc func(*T) error
	fileType  string
}

func NewYAMLWriterDecoder[T any](fileType string, check func(*T) error) *YAMLWriterDecoder[T] {
	return &YAMLWriterDecoder[T]{
		checkFunc: check,
		fileType:  fileType,
	}
}

func (d *YAMLWriterDecoder[T]) Decode() (any, error) {
	obj := new(T)
	err := yaml.NewDecoder(d).Decode(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return obj, d.checkFunc(obj)
}
func (d *YAMLWriterDecoder[T]) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

func (d *YAMLWriterDecoder[T]) FileType() string {
	return d.fileType
}

func Example() {
	type Person struct {
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
		Age       int    `json:"age"`
	}

	decoder := NewJSONWriterDecoder[Person]("Person", func(p *Person) error {
		if p.FirstName == "" {
			return ErrFailedCheck
		}
		return nil
	})

	samplePerson := &Person{FirstName: "Tony", LastName: "Stark", Age: 53}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(samplePerson)

	_, _ = decoder.ReadFrom(buf)
	p, err := decoder.Decode()
	if err != nil {
		panic(err)
	}
	decodedPerson, ok := p.(*Person)
	if !ok {
		panic("invalid type")
	}

	fmt.Printf("%s %s %d", decodedPerson.FirstName, decodedPerson.LastName, decodedPerson.Age)

	// Output: Tony Stark 53

}
