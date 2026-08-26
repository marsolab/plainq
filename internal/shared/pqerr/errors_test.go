package pqerr

import "testing"

func TestError_Error(t *testing.T) {
	type tcase struct {
		err  Error
		want string
	}

	tests := map[string]tcase{
		"ErrInvalidID":        {err: ErrInvalidID, want: "invalid id"},
		"ErrAlreadyExists":    {err: ErrAlreadyExists, want: "already exist"},
		"ErrInvalidBatchSize": {err: ErrInvalidBatchSize, want: "invalid batch size"},
		"ErrCapacityExceeded": {err: ErrCapacityExceeded, want: "request exceeds capacity"},
		"ErrNotFound":         {err: ErrNotFound, want: "not found"},
		"Custom":              {err: Error("test error"), want: "test error"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.err.Error(); got != tc.want {
				t.Errorf("Error() = %v, want %v", got, tc.want)
			}
		})
	}
}
