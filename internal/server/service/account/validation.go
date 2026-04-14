package account

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/marsolab/servekit/errkit"
)

const (
	minNameLen, maxNameLen = 2, 50
	minPassLen, maxPassLen = 6, 50
)

// validateUserName validates given name.
func validateUserName(name string) error {
	if err := charLenMinMax(name, minNameLen, maxNameLen); err != nil {
		return errkit.ErrValidation
	}

	if strings.ContainsAny(name, "@/\"'?,:;<>!#$%^&*()={}[]|") {
		return errkit.ErrValidation
	}

	return nil
}

// validatePassword validates given password.
func validatePassword(password string) error {
	if err := charLenMinMax(password, minPassLen, maxPassLen); err != nil {
		return errkit.ErrValidation
	}

	return nil
}

// validateEmail validates given email.
func validateEmail(email string) error {
	// If contains special characters then invalid.
	if strings.ContainsAny(email, "/\"'?,:;<>!#$%^&*()={}[]|") || !strings.Contains(email, "@") {
		return errkit.ErrValidation
	}

	if tail := email[len(email)-1]; strings.Contains(string(tail), ".") {
		return errkit.ErrValidation
	}

	parts := strings.Split(email, "@")
	if len(parts) < 2 {
		return errkit.ErrValidation
	}

	domparts := strings.Split(parts[1], ".")
	if len(domparts) < 2 || domparts[0] == "" || domparts[1] == "" {
		return errkit.ErrValidation
	}

	return nil
}

// charLenMinMax returns non nil error if given password is too short or to long.
func charLenMinMax(value string, min, max int) error {
	valueLen := utf8.RuneCountInString(value)
	if valueLen < min {
		return fmt.Errorf("%w: value is to short", errkit.ErrValidation)
	}

	if valueLen > max {
		return fmt.Errorf("%w: value is to long", errkit.ErrValidation)
	}

	return nil
}
