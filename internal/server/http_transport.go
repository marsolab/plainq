package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/plainq/plainq/internal/houston"
	"github.com/plainq/plainq/internal/server/auth"
	"github.com/plainq/plainq/internal/server/middleware"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/servekit/errkit"
	"github.com/plainq/servekit/respond"
)

func (s *PlainQ) createQueueHandler(w http.ResponseWriter, r *http.Request) {
	// Queue creation requires admin role.
	if s.permissionService != nil {
		claims, ok := middleware.GetClaimsFromContext(r.Context())
		if !ok || !auth.IsAdmin(claims.Roles) {
			http.Error(w, `{"error": "admin role required to create queues"}`, http.StatusForbidden)
			return
		}
	}

	var input v1.CreateQueueRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respond.ErrorHTTP(w, r, err)
		return
	}

	defer func() {
		if err := r.Body.Close(); err != nil {
			s.logger.Error("create queue: close request body",
				slog.String("error", err.Error()),
			)
		}
	}()

	output, createErr := s.storage.CreateQueue(r.Context(), &input)
	if createErr != nil {
		respond.ErrorHTTP(w, r, createErr)
		return
	}

	respond.JSON(w, r, output, respond.WithStatus(http.StatusCreated))
}

func (s *PlainQ) listQueuesHandler(w http.ResponseWriter, r *http.Request) {
	input := v1.ListQueuesRequest{
		QueuePrefix: r.URL.Query().Get("prefix"),
		Cursor:      r.URL.Query().Get("cursor"),
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		limit, parseErr := strconv.Atoi(l)
		if parseErr != nil {
			respond.ErrorHTTP(w, r, fmt.Errorf("%w: invalid limit", errkit.ErrInvalidArgument))
			return
		}

		if limit < 1 {
			respond.ErrorHTTP(w, r, fmt.Errorf("%w: invalid limit", errkit.ErrInvalidArgument))
			return
		}

		if limit > math.MaxInt32 {
			respond.ErrorHTTP(w, r, fmt.Errorf("%w: limit value too large", errkit.ErrInvalidArgument))
			return
		}
		//nolint:gosec // Safe: value checked against MaxInt32 above
		input.Limit = int32(limit)
	}

	output, listErr := s.storage.ListQueues(r.Context(), &input)
	if listErr != nil {
		respond.ErrorHTTP(w, r, listErr)
		return
	}

	respond.JSON(w, r, output)
}

func (s *PlainQ) describeQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		respond.ErrorHTTP(w, r, err)
		return
	}

	input := v1.DescribeQueueRequest{QueueId: id}

	output, describeErr := s.storage.DescribeQueue(r.Context(), &input)
	if describeErr != nil {
		respond.ErrorHTTP(w, r, describeErr)
		return
	}

	respond.JSON(w, r, output, respond.WithStatus(http.StatusOK))
}

func (s *PlainQ) deleteQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		respond.ErrorHTTP(w, r, fmt.Errorf("validation error: %w", err))
		return
	}

	// Check delete permission.
	if s.permissionService != nil {
		claims, ok := middleware.GetClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if err := s.permissionService.CheckQueuePermission(r.Context(), id, claims.Roles, auth.ActionDelete); err != nil {
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusForbidden)
			return
		}
	}

	force, parseErr := strconv.ParseBool(r.URL.Query().Get("force"))
	if parseErr != nil {
		force = false
	}

	input := v1.DeleteQueueRequest{
		QueueId: id,
		Force:   force,
	}

	output, deleteErr := s.storage.DeleteQueue(r.Context(), &input)
	if deleteErr != nil {
		respond.ErrorHTTP(w, r, deleteErr)
		return
	}

	respond.JSON(w, r, output, respond.WithStatus(http.StatusOK))
}

func (s *PlainQ) purgeQueueHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if err := validateQueueID(id); err != nil {
		respond.ErrorHTTP(w, r, fmt.Errorf("validation error: %w", err))
		return
	}

	// Check purge permission.
	if s.permissionService != nil {
		claims, ok := middleware.GetClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}
		if err := s.permissionService.CheckQueuePermission(r.Context(), id, claims.Roles, auth.ActionPurge); err != nil {
			http.Error(w, `{"error": "`+err.Error()+`"}`, http.StatusForbidden)
			return
		}
	}

	output, purgeErr := s.storage.PurgeQueue(r.Context(), &v1.PurgeQueueRequest{
		QueueId: id,
	})
	if purgeErr != nil {
		respond.ErrorHTTP(w, r, purgeErr)
		return
	}

	respond.JSON(w, r, output, respond.WithStatus(http.StatusOK))
}

func (*PlainQ) houstonStaticHandler(w http.ResponseWriter, r *http.Request) {
	routeCtx := chi.RouteContext(r.Context())
	pathPrefix := strings.TrimSuffix(routeCtx.RoutePattern(), "/*")

	http.StripPrefix(pathPrefix, http.FileServerFS(houston.Bundle())).ServeHTTP(w, r)
}
