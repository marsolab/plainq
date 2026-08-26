//nolint:contextcheck // policyHTTPContext always derives from the request's context and only adds bounded metadata.
package queue

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/httpkit"
)

func (s *Service) listTopicsHandler(w http.ResponseWriter, r *http.Request) {
	output, err := s.pubsub.listTopics(s.policyHTTPContext(r), &ListTopicsRequest{})
	if err != nil {
		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, output)
}

func (s *Service) createTopicHandler(w http.ResponseWriter, r *http.Request) {
	defer s.closeBody(r, "create topic")

	var input CreateTopicRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	output, err := s.pubsub.createTopic(s.policyHTTPContext(r), &input)
	if err != nil {
		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) deleteTopicHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.pubsub.deleteTopic(s.policyHTTPContext(r), chi.URLParam(r, "topicID")); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, map[string]any{}, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) subscribeTopicHandler(w http.ResponseWriter, r *http.Request) {
	defer s.closeBody(r, "subscribe topic")

	var input SubscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	output, err := s.pubsub.subscribe(s.policyHTTPContext(r), chi.URLParam(r, "topicID"), &input)
	if err != nil {
		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) unsubscribeTopicHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.pubsub.unsubscribe(
		s.policyHTTPContext(r),
		chi.URLParam(r, "topicID"),
		chi.URLParam(r, "subscriptionID"),
	); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, map[string]any{}, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) publishTopicHandler(w http.ResponseWriter, r *http.Request) {
	defer s.closeBody(r, "publish topic")

	var input PublishRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		queueHTTPError(w, r, err)

		return
	}

	output, err := s.pubsub.publish(s.policyHTTPContext(r), chi.URLParam(r, "topicID"), &input)
	if err != nil {
		if errors.Is(err, pqerr.ErrCapacityExceeded) {
			queueHTTPError(w, r, err, httpkit.WithStatus(http.StatusRequestEntityTooLarge))

			return
		}

		queueHTTPError(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusAccepted))
}
