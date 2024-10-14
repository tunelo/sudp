package sudp

import "fmt"

type Err struct {
	message string
	err     error
}

func newError(m string, e error) error {
	return &Err{
		message: m,
		err:     e,
	}
}

func (e *Err) Error() string {
	if e.err != nil {
		return fmt.Sprintf("%s, %v", e.message, e.err)
	} else {
		return fmt.Sprintf("%s", e.message)
	}
}
