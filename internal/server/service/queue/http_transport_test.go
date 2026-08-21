package queue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/middleware"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
)

// validXID is a well-formed 20-char XID used to satisfy validateQueueID.
const validXID = "9m4e2mr0ui3e8a215n4g"

func newTestService(storage Storage) *Service {
	svc := NewService(nil, logkit.NewNop(), storage)
	svc.SetPermissionChecker(testPermissionCheckerFunc(func(
		context.Context, string, string, middleware.PermissionType,
	) (bool, error) {
		return true, nil
	}))

	return svc
}

type testPermissionCheckerFunc func(context.Context, string, string, middleware.PermissionType) (bool, error)

func (f testPermissionCheckerFunc) HasQueuePermission(
	ctx context.Context, userID, queueID string, permission middleware.PermissionType,
) (bool, error) {
	return f(ctx, userID, queueID, permission)
}

func doRequest(t *testing.T, svc *Service, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, middleware.UserInfo{
		UserID: "user-1", Roles: []string{"member"}, TenantID: "tenant-1",
	}))
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)

	return rec
}

func TestServiceQueueMutationRoutesEnforcePermissionAndResolveAdminTenant(t *testing.T) {
	storageCalled := false
	svc := NewService(nil, logkit.NewNop(), &mockStorage{
		sendFunc: func(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
			storageCalled = true

			return &v1.SendResponse{}, nil
		},
	})

	var gotUserID, gotQueueID string
	var gotPermission middleware.PermissionType
	svc.SetPermissionChecker(testPermissionCheckerFunc(func(
		_ context.Context, userID, queueID string, permission middleware.PermissionType,
	) (bool, error) {
		gotUserID, gotQueueID, gotPermission = userID, queueID, permission

		return false, nil
	}))

	req := httptest.NewRequest(http.MethodPost, "/"+validXID+"/messages", strings.NewReader(
		`{"messages":[{"body":"aGVsbG8="}]}`,
	))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserContextKey, middleware.UserInfo{
		UserID: "admin-1", Roles: []string{"admin"}, TenantID: "tenant-1",
	}))
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("permission denied status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	if storageCalled {
		t.Fatal("send storage called despite denied permission")
	}
	if gotUserID != "admin-1" || gotQueueID != validXID || gotPermission != middleware.PermissionSend {
		t.Fatalf("permission check = (%q, %q, %q)", gotUserID, gotQueueID, gotPermission)
	}
}

func TestServiceQueueMutationRoutesRemainOpenWhenAuthenticationIsDisabled(t *testing.T) {
	storageCalled := false
	svc := NewService(&config.Config{AuthEnable: false}, logkit.NewNop(), &mockStorage{
		sendFunc: func(context.Context, *v1.SendRequest) (*v1.SendResponse, error) {
			storageCalled = true

			return &v1.SendResponse{}, nil
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/"+validXID+"/messages", strings.NewReader(
		`{"messages":[{"body":"aGVsbG8="}]}`,
	))
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("auth-disabled send status = %d, want %d", rec.Code, http.StatusCreated)
	}
	if !storageCalled {
		t.Fatal("auth-disabled send did not reach storage")
	}
}

func TestService_SendMessagesHandler(t *testing.T) {
	type tcase struct {
		storage    *mockStorage
		target     string
		body       string
		wantStatus int
	}

	tests := map[string]tcase{
		"OK": {
			storage: &mockStorage{
				sendFunc: func(_ context.Context, input *v1.SendRequest) (*v1.SendResponse, error) {
					td.Cmp(t, input.QueueId, validXID)
					td.Cmp(t, len(input.Messages), 1)

					return &v1.SendResponse{MessageIds: []string{"m1"}}, nil
				},
			},
			target:     "/" + validXID + "/messages",
			body:       `{"messages":[{"body":"aGVsbG8="}]}`,
			wantStatus: http.StatusCreated,
		},
		"InvalidQueueID": {
			storage:    &mockStorage{},
			target:     "/not-a-valid-id/messages",
			body:       `{"messages":[{"body":"aGVsbG8="}]}`,
			wantStatus: http.StatusBadRequest,
		},
		"EmptyMessages": {
			storage:    &mockStorage{},
			target:     "/" + validXID + "/messages",
			body:       `{"messages":[]}`,
			wantStatus: http.StatusBadRequest,
		},
		"StorageError": {
			storage: &mockStorage{
				sendFunc: func(_ context.Context, _ *v1.SendRequest) (*v1.SendResponse, error) {
					return nil, errors.New("boom")
				},
			},
			target:     "/" + validXID + "/messages",
			body:       `{"messages":[{"body":"aGVsbG8="}]}`,
			wantStatus: http.StatusInternalServerError,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(t, newTestService(tc.storage), http.MethodPost, tc.target, tc.body)
			td.Cmp(t, rec.Code, tc.wantStatus)
		})
	}
}

func TestService_ReceiveMessagesHandler(t *testing.T) {
	type tcase struct {
		storage    *mockStorage
		target     string
		wantStatus int
	}

	tests := map[string]tcase{
		"OK_DefaultBatch": {
			storage: &mockStorage{
				receiveFunc: func(_ context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
					td.Cmp(t, input.BatchSize, uint32(1))

					return &v1.ReceiveResponse{Messages: []*v1.ReceiveMessage{{Id: "m1", Body: []byte("hi")}}}, nil
				},
			},
			target:     "/" + validXID + "/messages/receive",
			wantStatus: http.StatusOK,
		},
		"OK_ExplicitBatch": {
			storage: &mockStorage{
				receiveFunc: func(_ context.Context, input *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
					td.Cmp(t, input.BatchSize, uint32(5))

					return &v1.ReceiveResponse{}, nil
				},
			},
			target:     "/" + validXID + "/messages/receive?batch=5",
			wantStatus: http.StatusOK,
		},
		"BatchTooLarge": {
			storage:    &mockStorage{},
			target:     "/" + validXID + "/messages/receive?batch=99",
			wantStatus: http.StatusBadRequest,
		},
		"BatchNotANumber": {
			storage:    &mockStorage{},
			target:     "/" + validXID + "/messages/receive?batch=abc",
			wantStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(t, newTestService(tc.storage), http.MethodPost, tc.target, "")
			td.Cmp(t, rec.Code, tc.wantStatus)
		})
	}
}

func TestService_DeleteQueueHandlerFailedPrecondition(t *testing.T) {
	svc := newTestService(&mockStorage{
		deleteQueueFunc: func(context.Context, *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
			return nil, pqerr.ErrFailedPrecondition
		},
	})

	rec := doRequest(t, svc, http.MethodDelete, "/"+validXID, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("DeleteQueue status = %d, want %d", rec.Code, http.StatusConflict)
	}
}

func TestService_AckMessagesHandler(t *testing.T) {
	type tcase struct {
		storage    *mockStorage
		body       string
		wantStatus int
	}

	tests := map[string]tcase{
		"OK": {
			storage: &mockStorage{
				deleteFunc: func(_ context.Context, input *v1.DeleteRequest) (*v1.DeleteResponse, error) {
					td.Cmp(t, input.QueueId, validXID)
					td.Cmp(t, input.MessageIds, []string{"m1", "m2"})

					return &v1.DeleteResponse{Successful: []string{"m1", "m2"}}, nil
				},
			},
			body:       `{"messageIds":["m1","m2"]}`,
			wantStatus: http.StatusOK,
		},
		"EmptyIDs": {
			storage:    &mockStorage{},
			body:       `{"messageIds":[]}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(t, newTestService(tc.storage), http.MethodPost, "/"+validXID+"/messages/ack", tc.body)
			td.Cmp(t, rec.Code, tc.wantStatus)
		})
	}
}

func TestService_PeekMessagesHandler(t *testing.T) {
	type tcase struct {
		storage    *mockStorage
		target     string
		wantStatus int
	}

	tests := map[string]tcase{
		"OK_Defaults": {
			storage: &mockStorage{
				peekFunc: func(_ context.Context, input *PeekRequest) (*PeekResponse, error) {
					td.Cmp(t, input.QueueID, validXID)
					td.Cmp(t, input.Limit, defaultPeekLimit)
					td.Cmp(t, input.Offset, uint32(0))

					return &PeekResponse{
						Messages: []*PeekMessage{{ID: "m1", Body: []byte("hi"), Retries: 1, InFlight: true}},
						Total:    1,
					}, nil
				},
			},
			target:     "/" + validXID + "/messages",
			wantStatus: http.StatusOK,
		},
		"OK_LimitClamped": {
			storage: &mockStorage{
				peekFunc: func(_ context.Context, input *PeekRequest) (*PeekResponse, error) {
					td.Cmp(t, input.Limit, maxPeekLimit)
					td.Cmp(t, input.Offset, uint32(10))

					return &PeekResponse{}, nil
				},
			},
			target:     "/" + validXID + "/messages?limit=999999&offset=10",
			wantStatus: http.StatusOK,
		},
		"InvalidLimit": {
			storage:    &mockStorage{},
			target:     "/" + validXID + "/messages?limit=0",
			wantStatus: http.StatusBadRequest,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			rec := doRequest(t, newTestService(tc.storage), http.MethodGet, tc.target, "")
			td.Cmp(t, rec.Code, tc.wantStatus)
		})
	}
}
