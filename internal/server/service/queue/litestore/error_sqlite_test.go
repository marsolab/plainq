//go:build cgo

package litestore

import (
	"errors"
	"testing"

	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/mattn/go-sqlite3"
)

func TestSQLitePubSubErrorNormalization(t *testing.T) {
	tests := map[string]struct {
		err       error
		operation pubSubErrorContext
		want      error
	}{
		"create constraint is duplicate":    {sqlite3.Error{Code: sqlite3.ErrConstraint}, pubSubCreateTopic, pqerr.ErrAlreadyExists},
		"subscribe constraint is duplicate": {sqlite3.Error{Code: sqlite3.ErrConstraint}, pubSubSubscribe, pqerr.ErrAlreadyExists},
		"foreign key is missing parent":     {sqlite3.Error{Code: sqlite3.ErrConstraint, ExtendedCode: sqlite3.ErrConstraintForeignKey}, pubSubSubscribe, pqerr.ErrNotFound},
		"busy is unavailable":               {sqlite3.Error{Code: sqlite3.ErrBusy}, pubSubListTopics, pqerr.ErrUnavailable},
		"locked is unavailable":             {sqlite3.Error{Code: sqlite3.ErrLocked}, pubSubInventory, pqerr.ErrUnavailable},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := normalizePubSubError(tc.err, tc.operation)
			if !errors.Is(got, tc.want) {
				t.Fatalf("normalizePubSubError(%v, %q) = %v, want %v", tc.err, tc.operation, got, tc.want)
			}
		})
	}
}
