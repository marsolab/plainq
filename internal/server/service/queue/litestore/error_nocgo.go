//go:build !cgo

package litestore

func normalizeSQLiteDriverPubSubError(err error, _ pubSubErrorContext) error {
	return err
}
