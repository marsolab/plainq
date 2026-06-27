package queue

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/logkit"
	"github.com/maxatome/go-testdeep/td"
)

// validXID is a well-formed 20-char XID used to satisfy validateQueueID.
const validXID = "9m4e2mr0ui3e8a215n4g"

func newTestService(storage Storage) *Service {
	return NewService(nil, logkit.NewNop(), storage)
}

func doRequest(t *testing.T, svc *Service, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	svc.ServeHTTP(rec, req)

	return rec
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
