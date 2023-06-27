package validate

import (
	"errors"
	"fmt"
	"io"
)

var ErrValidation = errors.New("validation error")
var ErrInput = errors.New("validation input error")
type WriterDecoder interface {
	io.Writer
	Decode() (any, error)
}

type Validator[ObjectT any, ConfigT any] struct {
	validateFunction func(ObjectT, ConfigT) error
	objectDecoder    WriterDecoder
	configDecoder    WriterDecoder
}

func (v *Validator[ObjectT, ConfigT]) Validate(obj any, config any) error {
	objT, ok := obj.(ObjectT)
	if !ok {
		return fmt.Errorf("%w: invalid input object type %T", ErrInput, obj)
	}
	configT, ok := config.(ConfigT)
	if !ok {
		return fmt.Errorf("%w: invalid config object type %T", ErrInput, config)
	}

	return v.validateFunction(objT, configT)
}
func (v *Validator[ObjectT, ConfigT]) ValidateFrom(objReader io.Reader, configReader io.Reader) error {
	_, _ = io.Copy(v.objectDecoder, objReader)
	_, _ = io.Copy(v.configDecoder, configReader)

	o, err := v.objectDecoder.Decode()
	obj, ok := o.(*ObjectT)
	if !ok {
		return fmt.Errorf("%w: invalid object type %T, possible decoding error: %v", ErrInput, o, err)
	}

	c, err := v.configDecoder.Decode()
	config, ok := c.(*ConfigT)
	if !ok {
		return fmt.Errorf("%w: invalid config type %T, possible decoding error: %v", ErrInput, o, err)
	}

	return v.validateFunction(*obj, *config)
}

func (v *Validator[ObjectT, ConfigT]) WithDecoders(objectDecoder WriterDecoder, configDecoder WriterDecoder) *Validator[ObjectT, ConfigT] {
	v.objectDecoder = objectDecoder
	v.configDecoder = configDecoder
	return v
}

func NewValidator[ValidateT any, ConfigT any](validateFunction func(ValidateT, ConfigT) error) *Validator[ValidateT, ConfigT] {
	return &Validator[ValidateT, ConfigT]{validateFunction: validateFunction, objectDecoder: nil, configDecoder: nil}
}

