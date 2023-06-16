package artifact

type Validator struct {
	config *Config
}

func NewValidator(c *Config) *Validator {
	return &Validator{config: c}
}

func (v *Validator) Validate(a Artifact) error {
	return nil
}

// func ExampleValidator() {
// 	validator := NewValidator(NewConfig())
//
// 	// validator.Validate()
// }
