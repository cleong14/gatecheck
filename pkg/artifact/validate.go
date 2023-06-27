package artifact

import (
	"bytes"
	"context"
	"errors"
	"os"
)

var ErrValidation = errors.New("validation error")

type ValidateFunction func(Config, any) error

type Validator struct {
	bytes.Buffer
	config         Config
	validatorFuncs map[TypeID]ValidateFunction
}

func NewValidator(c Config) *Validator {
	return &Validator{config: c, validatorFuncs: ValidatorFunctions}
}

func (v *Validator) Decode() (any, error) {
	decoder := new(AsyncDecoder).WithDecoders(StandardDecoders()...)
	decoder.ReadFrom(v)
	return decoder.Decode(context.Background())
}

func (v *Validator) Validate() error {
	a, _ := v.Decode()
	return v.validate(a)
}

func (v *Validator) validate(a any) error {

	validate, ok := v.validatorFuncs[GatecheckTypeID(a)]
	// Would be a bundle or config file
	if !ok {
		return nil
	}
	return validate(v.config, a)
}

func ExampleValidator() {
	config := NewConfig()

	f, err := os.Open("../../test/grype-report.json")
	if err != nil {
		panic(err)
	}

	validator := NewValidator(*config)
	_, _ = validator.ReadFrom(f)
	// Expect no validation errors
	if err := validator.Validate(); err != nil {
		panic(err)
	}

	config.Grype.High = 0

	// Expect validation errors
	if err := validator.Validate(); err == nil {
		panic(err)
	}
}
