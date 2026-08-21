package pqerr

// Compilation time check for interface implementation.
var _ error = Error("") //nolint: errcheck

const (
	// ErrInvalidID shows that identifier is invalid.
	ErrInvalidID Error = "invalid id"

	// ErrInvalidInput shows that input data is invalid.
	ErrInvalidInput Error = "invalid input"

	// ErrNotFound shows that requested resource has not been found.
	ErrNotFound Error = "not found"

	// ErrAlreadyExists shows that it is impossible to create a resource because
	// it already exists.
	ErrAlreadyExists Error = "already exist"

	// ErrFailedPrecondition shows that the resource is in a state that does
	// not permit the requested operation.
	ErrFailedPrecondition Error = "failed precondition"

	// ErrUnauthenticated indicates the request does not have valid
	// authentication credentials to perform the operation.
	ErrUnauthenticated Error = "authentication failed"

	// ErrUnauthorized indicates the caller does not have permission to
	// execute the specified operation. It must not be used if the caller
	// cannot be identified (use ErrUnauthenticated instead for those errors).
	ErrUnauthorized Error = "permission denied"

	// ErrUnavailable indicates that the service is currently unavailable.
	// This kind of error is retryable. Caller should retry with a backoff.
	ErrUnavailable Error = "temporarily unavailable"

	// Transport related errors.

	// ErrGracefulShutdown indicates that it is not possible to shut down
	// the server in a graceful way.
	ErrGracefulShutdown Error = "graceful shutdown failed"

	// Les generic errors.

	// ErrInvalidBatchSize shows that batch size exceeding the allowed limits.
	ErrInvalidBatchSize Error = "invalid batch size"
)

// Error represents server errors and implements go builtin error interface.
type Error string

func (e Error) Error() string { return string(e) }
