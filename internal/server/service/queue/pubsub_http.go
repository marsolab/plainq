package queue

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/marsolab/servekit/httpkit"
)

func (s *Service) listTopicsHandler(w http.ResponseWriter, r *http.Request) {
	output, err := s.storage.ListTopics(r.Context())
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, output)
}

func (s *Service) createTopicHandler(w http.ResponseWriter, r *http.Request) {
	var input CreateTopicRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("create topic: close request body", slog.String("error", err.Error()))
		}
	}()

	output, err := s.storage.CreateTopic(r.Context(), &input)
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) deleteTopicHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.storage.DeleteTopic(r.Context(), chi.URLParam(r, "topicID")); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, map[string]any{}, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) subscribeTopicHandler(w http.ResponseWriter, r *http.Request) {
	var input SubscribeRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("subscribe topic: close request body", slog.String("error", err.Error()))
		}
	}()

	if err := validateQueueID(input.QueueID); err != nil {
		httpkit.ErrorHTTP(w, r, fmt.Errorf("validation error: %w", err))

		return
	}

	output, err := s.storage.Subscribe(r.Context(), chi.URLParam(r, "topicID"), &input)
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusCreated))
}

func (s *Service) unsubscribeTopicHandler(w http.ResponseWriter, r *http.Request) {
	if err := s.storage.Unsubscribe(r.Context(), chi.URLParam(r, "topicID"), chi.URLParam(r, "subscriptionID")); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, map[string]any{}, httpkit.WithStatus(http.StatusOK))
}

func (s *Service) publishTopicHandler(w http.ResponseWriter, r *http.Request) {
	var input PublishRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("publish topic: close request body", slog.String("error", err.Error()))
		}
	}()

	output, err := s.storage.Publish(r.Context(), chi.URLParam(r, "topicID"), &input)
	if err != nil {
		httpkit.ErrorHTTP(w, r, err)

		return
	}

	httpkit.JSON(w, r, output, httpkit.WithStatus(http.StatusAccepted))
}
