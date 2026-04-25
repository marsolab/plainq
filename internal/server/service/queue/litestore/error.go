package litestore

const (
	// ErrQueueEmpty shows that requested queue is empty.
	ErrQueueEmpty Error = "queue is empty"
)

// Error represents package level errors related to the storage engine.
type Error string

func (e Error) Error() string { return string(e) }

const (
	fmtBeginTxError  = "begin transaction: %w"
	fmtCommitTxError = "commit transaction: %w"
)
