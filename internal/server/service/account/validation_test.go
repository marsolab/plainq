package account

import (
	"testing"

	"github.com/maxatome/go-testdeep/td"
	"github.com/marsolab/servekit/errkit"
)

func TestValidateUserName(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr error
	}{
		"valid name": {
			input:   "John Doe",
			wantErr: nil,
		},
		"valid name with numbers": {
			input:   "User123",
			wantErr: nil,
		},
		"valid name with spaces": {
			input:   "John Smith Jr",
			wantErr: nil,
		},
		"too short": {
			input:   "a",
			wantErr: errkit.ErrValidation,
		},
		"too long": {
			input:   "ThisNameIsWayTooLongAndShouldFailValidationBecauseItExceedsTheMaximumLength",
			wantErr: errkit.ErrValidation,
		},
		"contains special chars": {
			input:   "User@Name",
			wantErr: errkit.ErrValidation,
		},
		"contains slash": {
			input:   "User/Name",
			wantErr: errkit.ErrValidation,
		},
		"contains quotes": {
			input:   "User\"Name",
			wantErr: errkit.ErrValidation,
		},
		"contains brackets": {
			input:   "User[Name]",
			wantErr: errkit.ErrValidation,
		},
		"empty string": {
			input:   "",
			wantErr: errkit.ErrValidation,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) { 
			td.Cmp(t, validateUserName(tc.input), tc.wantErr)
		})
	}
}
