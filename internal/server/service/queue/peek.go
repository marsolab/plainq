package queue

const (
	// maxReceiveBatchSize bounds how many messages a single Receive (consume)
	// call may claim. It mirrors the gRPC Receive contract (1–10).
	maxReceiveBatchSize uint32 = 10

	// defaultPeekLimit is the page size used when a browse request omits limit.
	defaultPeekLimit uint32 = 50

	// maxPeekLimit caps how many messages a single browse may return so a
	// deep queue cannot be paged in one unbounded scan.
	maxPeekLimit uint32 = 1000
)

// PeekRequest describes a non-consuming browse of a queue's messages.
//
// Unlike Receive, a peek leaves visibility deadlines and retry counts
// untouched, so opening the admin UI never hides or consumes traffic.
type PeekRequest struct {
	// QueueID is the queue to browse.
	QueueID string

	// Limit is the maximum number of messages to return. Zero means
	// defaultPeekLimit; values above maxPeekLimit are clamped by the storage.
	Limit uint32

	// Offset is the number of messages to skip, ordered oldest-first.
	Offset uint32
}

// PeekMessage is a single message as seen by a browse (peek) request.
type PeekMessage struct {
	// ID is the message identifier.
	ID string `json:"id"`

	// Body is the raw message payload. It is base64-encoded on the wire, the
	// same as ReceiveMessage.body.
	Body []byte `json:"body"`

	// CreatedAt is the message enqueue timestamp, formatted by the backend.
	CreatedAt string `json:"createdAt"`

	// VisibleAt is the timestamp the message next becomes visible to receivers.
	VisibleAt string `json:"visibleAt"`

	// Retries is the number of times the message has been received.
	Retries uint32 `json:"retries"`

	// InFlight reports whether the message is currently invisible (claimed by
	// a consumer and inside its visibility timeout).
	InFlight bool `json:"inFlight"`
}

// PeekResponse is the result of a browse (peek) request.
type PeekResponse struct {
	// Messages is the page of browsed messages, oldest-first.
	Messages []*PeekMessage `json:"messages"`

	// Total is the total number of messages in the queue, independent of the
	// limit/offset window — useful for paginating the admin UI.
	Total uint64 `json:"total"`
}
