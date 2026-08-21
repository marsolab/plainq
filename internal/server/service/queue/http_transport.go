//nolint:contextcheck // policyHTTPContext always derives from the request's context and only adds bounded metadata.
package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/quota"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

func (s *Service) createQueueHandler(w http.ResponseWriter, r *http.Request) {
	var input v1.CreateQueueRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("create queue: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	output, createErr := s.policyOperations().CreateQueue(s.policyHTTPContext(r), &input)
	if createErr != nil {
		queueHTTPError(w, r, createErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) listQueuesHandler(w http.ResponseWriter, r *http.Request) {
	input := v1.ListQueuesRequest{
		QueuePrefix: r.URL.Query().Get("prefix"),
		Cursor:      r.URL.Query().Get("cursor"),
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		limit, parseErr := strconv.Atoi(l)
		if parseErr != nil {
			queueHTTPError(w, r, fmt.Errorf("%w: invalid limit", errkit.ErrInvalidArgument))

			return
		}

		if limit < 1 {
			queueHTTPError(w, r, fmt.Errorf("%w: invalid limit", errkit.ErrInvalidArgument))

			return
		}

		if limit > math.MaxInt32 {
			queueHTTPError(w, r, fmt.Errorf("%w: limit too large", errkit.ErrInvalidArgument))

			return
		}

		input.Limit = int32(limit) //nolint:gosec // limit was validated against math.MaxInt32 above.
	}

	output, listErr := s.policyOperations().ListQueues(s.policyHTTPContext(r), &input)
	if listErr != nil {
		queueHTTPError(w, r, listErr)

		return
	}

	httpkit.JSON(w, r, output)
}

func (s *Service) describeQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	input := v1.DescribeQueueRequest{QueueId: id}

	output, describeErr := s.policyOperations().DescribeQueue(s.policyHTTPContext(r), &input)
	if describeErr != nil {
		queueHTTPError(w, r, describeErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) deleteQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("validation error: %w", err))

		return
	}

	force, parseErr := strconv.ParseBool(r.URL.Query().Get("force"))
	if parseErr != nil {
		force = false
	}

	input := v1.DeleteQueueRequest{
		QueueId: id,
		Force:   force,
	}

	output, deleteErr := s.policyOperations().DeleteQueue(s.policyHTTPContext(r), &input)
	if deleteErr != nil {
		if pqerr.IsFailedPrecondition(deleteErr) {
			queueHTTPError(w, r, deleteErr, httpkit.WithStatus(http.StatusConflict))

			return
		}

		queueHTTPError(w, r, deleteErr)

		return
	}

	s.reconcileTopicSubscriptionCounts(r.Context())

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) purgeQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("validation error: %w", err))

		return
	}

	output, purgeErr := s.policyOperations().PurgeQueue(s.policyHTTPContext(r), &v1.PurgeQueueRequest{
		QueueId: id,
	})
	if purgeErr != nil {
		queueHTTPError(w, r, purgeErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

// sendMessagesHandler enqueues one or more messages. The request body matches
// the gRPC SendRequest shape ({"messages":[{"body":"<base64>"}]}); the queue id
// always comes from the URL.
func (s *Service) sendMessagesHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("%w: invalid queue id", errkit.ErrInvalidArgument))

		return
	}

	var input v1.SendRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	defer s.closeBody(r, "send messages")

	input.QueueId = id

	if len(input.Messages) == 0 {
		queueHTTPError(w, r, fmt.Errorf("%w: at least one message is required", errkit.ErrInvalidArgument))

		return
	}

	output, sendErr := s.policyOperations().Send(s.policyHTTPContext(r), &input)
	if sendErr != nil {
		queueHTTPError(w, r, sendErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

// receiveMessagesHandler claims a batch of messages, making them invisible for
// the queue's visibility timeout. Batch size is taken from the ?batch= query
// parameter (1–10, default 1).
func (s *Service) receiveMessagesHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("%w: invalid queue id", errkit.ErrInvalidArgument))

		return
	}

	batch, batchErr := parseBatchSize(r.URL.Query().Get("batch"))
	if batchErr != nil {
		queueHTTPError(w, r, batchErr)

		return
	}

	output, recvErr := s.policyOperations().Receive(s.policyHTTPContext(r), &v1.ReceiveRequest{
		QueueId:   id,
		BatchSize: batch,
	})
	if recvErr != nil {
		queueHTTPError(w, r, recvErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

// ackMessagesHandler acknowledges (deletes) messages by id. The request body
// matches the gRPC DeleteRequest shape ({"messageIds":[...]}).
func (s *Service) ackMessagesHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("%w: invalid queue id", errkit.ErrInvalidArgument))

		return
	}

	var input v1.DeleteRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	defer s.closeBody(r, "ack messages")

	input.QueueId = id

	if len(input.MessageIds) == 0 {
		queueHTTPError(w, r, fmt.Errorf("%w: at least one message id is required", errkit.ErrInvalidArgument))

		return
	}

	output, deleteErr := s.policyOperations().Delete(s.policyHTTPContext(r), &input)
	if deleteErr != nil {
		queueHTTPError(w, r, deleteErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

// peekMessagesHandler browses messages without consuming them. limit/offset are
// taken from the query string (default limit defaultPeekLimit, capped at
// maxPeekLimit by the storage).
func (s *Service) peekMessagesHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		queueHTTPError(w, r, fmt.Errorf("%w: invalid queue id", errkit.ErrInvalidArgument))

		return
	}

	params, paramErr := parsePeekParams(r.URL.Query())
	if paramErr != nil {
		queueHTTPError(w, r, paramErr)

		return
	}

	output, peekErr := s.policyOperations().Peek(s.policyHTTPContext(r), &PeekRequest{
		QueueID: id,
		Limit:   params.limit,
		Offset:  params.offset,
	})
	if peekErr != nil {
		queueHTTPError(w, r, peekErr)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusOK))
}

// closeBody closes the request body, logging any error under the given op.
func (s *Service) closeBody(r *http.Request, op string) {
	if err := r.Body.Close(); err != nil {
		s.logger.Error(op+": close request body", slog.String("error", err.Error()))
	}
}

func (s *Service) policyHTTPContext(r *http.Request) context.Context {
	keys := append([]string(nil), r.Header.Values("Idempotency-Key")...)
	keys = append(keys, r.Header.Values("X-Idempotency-Key")...)

	return WithHTTPRequestPolicyMetadata(
		r.Context(), keys, r.Header.Get("X-Request-ID"), r.RemoteAddr, r.UserAgent(),
	)
}

func queueHTTPError(
	w http.ResponseWriter,
	r *http.Request,
	err error,
	options ...httpkit.ResponseOption,
) {
	if retryDelay, exhausted := quota.RetryDelay(err); exhausted {
		retrySeconds := int(math.Ceil(retryDelay.Seconds()))
		w.Header().Set("Retry-After", strconv.Itoa(retrySeconds))

		options = append(options, httpkit.WithStatus(http.StatusTooManyRequests))
	}

	httpkit.ErrorHTTP(w, r, pqerr.AsTransport(err), options...)
}

// parseBatchSize parses the receive batch-size query parameter. An empty value
// defaults to 1; values must be within 1..maxReceiveBatchSize.
func parseBatchSize(raw string) (uint32, error) {
	if raw == "" {
		return 1, nil
	}

	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid batch", errkit.ErrInvalidArgument)
	}

	//nolint:gosec // n is bounded to a small positive range below.
	if n < 1 || uint32(n) > maxReceiveBatchSize {
		return 0, fmt.Errorf("%w: batch must be between 1 and %d", errkit.ErrInvalidArgument, maxReceiveBatchSize)
	}

	return uint32(n), nil
}

// peekParams holds the parsed browse window.
type peekParams struct {
	limit  uint32
	offset uint32
}

// parsePeekParams parses limit/offset for a browse request, clamping limit to
// maxPeekLimit and defaulting an empty limit to defaultPeekLimit.
func parsePeekParams(q url.Values) (peekParams, error) {
	params := peekParams{limit: defaultPeekLimit}

	if raw := q.Get("limit"); raw != "" {
		n, parseErr := strconv.Atoi(raw)
		if parseErr != nil || n < 1 {
			return peekParams{}, fmt.Errorf("%w: invalid limit", errkit.ErrInvalidArgument)
		}

		if uint32(n) > maxPeekLimit { //nolint:gosec // n is a validated positive int.
			n = int(maxPeekLimit)
		}

		params.limit = uint32(n)
	}

	if raw := q.Get("offset"); raw != "" {
		n, parseErr := strconv.Atoi(raw)
		if parseErr != nil || n < 0 {
			return peekParams{}, fmt.Errorf("%w: invalid offset", errkit.ErrInvalidArgument)
		}

		params.offset = uint32(n) //nolint:gosec // validated non-negative above.
	}

	return params, nil
}
