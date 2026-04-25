package pgstore

const (
	// ErrQueueEmpty indicates the requested queue is empty.
	ErrQueueEmpty Error = "queue is empty"
)

// Error represents package-level errors.
type Error string

func (e Error) Error() string { return string(e) }

const (
	fmtBeginTxError = "begin transaction: %w"
)
