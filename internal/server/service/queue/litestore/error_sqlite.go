//go:build cgo

package litestore

import (
	"errors"

	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/mattn/go-sqlite3"
)

func normalizeSQLiteDriverPubSubError(err error, operation pubSubErrorContext) error {
	var sqliteErr sqlite3.Error
	if !errors.As(err, &sqliteErr) {
		return err
	}
	if sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked {
		return errors.Join(pqerr.ErrUnavailable, err)
	}
	if sqliteErr.Code != sqlite3.ErrConstraint {
		return err
	}

	switch operation {
	case pubSubCreateTopic:
		return errors.Join(pqerr.ErrAlreadyExists, err)
	case pubSubSubscribe:
		if sqliteErr.ExtendedCode == sqlite3.ErrConstraintForeignKey {
			return errors.Join(pqerr.ErrNotFound, err)
		}

		return errors.Join(pqerr.ErrAlreadyExists, err)
	default:
		return err
	}
}
