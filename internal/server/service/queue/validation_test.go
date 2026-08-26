package queue

import (
	"errors"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/idkit"
	"github.com/maxatome/go-testdeep/td"
)

func Test_validateIDFromRequest(t *testing.T) {
	type tcase struct {
		input   interface{ GetQueueId() string }
		wantErr error
	}

	tests := map[string]tcase{
		"NilInterface": {
			input:   nil,
			wantErr: errkit.ErrInvalidID,
		},

		"SendRequest": {
			input:   &v1.SendRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"SendRequest_err": {
			input:   &v1.SendRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},

		"ReceiveRequest": {
			input:   &v1.ReceiveRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"ReceiveRequest_err": {
			input:   &v1.ReceiveRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},

		"DeleteRequest": {
			input:   &v1.DeleteRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DeleteRequest_err": {
			input:   &v1.DeleteRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},

		"DescribeQueueRequest": {
			input:   &v1.DescribeQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DescribeQueueRequest_err": {
			input:   &v1.DescribeQueueRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},

		"DeleteQueueRequest": {
			input:   &v1.DeleteQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DeleteQueueRequest_err": {
			input:   &v1.DeleteQueueRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},

		"PurgeQueueRequest": {
			input:   &v1.PurgeQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"PurgeQueueRequest_err": {
			input:   &v1.PurgeQueueRequest{QueueId: "invalid-id"},
			wantErr: errkit.ErrInvalidID,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateQueueIDFromRequest(tc.input)
			td.CmpErrorIs(t, err, tc.wantErr)
		})
	}
}

func Test_validateQueueID(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		err := validateQueueID(idkit.XID())
		td.CmpErrorIs(t, err, nil)
	})

	t.Run("Error", func(t *testing.T) {
		err := validateQueueID("invalid-id")
		td.CmpErrorIs(t, err, errkit.ErrInvalidID)
	})

	t.Run("Empty", func(t *testing.T) {
		err := validateQueueID("")
		td.CmpErrorIs(t, err, errkit.ErrInvalidID)
	})
}

func TestValidateTopicIDRejectsMalformedXID(t *testing.T) {
	tests := map[string]struct {
		id      string
		wantErr bool
	}{
		"valid":     {id: idkit.XID()},
		"malformed": {id: "not-a-topic-id", wantErr: true},
		"empty":     {id: "", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateTopicID(tc.id)
			if tc.wantErr {
				if !errors.Is(err, pqerr.ErrInvalidID) {
					t.Fatalf("validateTopicID(%q) error = %v, want %v", tc.id, err, pqerr.ErrInvalidID)
				}

				return
			}

			if err != nil {
				t.Fatalf("validateTopicID(%q) error = %v, want nil", tc.id, err)
			}
		})
	}
}

func TestValidateSubscriptionIDRejectsMalformedXID(t *testing.T) {
	tests := map[string]struct {
		id      string
		wantErr bool
	}{
		"valid":     {id: idkit.XID()},
		"malformed": {id: "not-a-subscription-id", wantErr: true},
		"empty":     {id: "", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateSubscriptionID(tc.id)
			if tc.wantErr {
				if !errors.Is(err, pqerr.ErrInvalidID) {
					t.Fatalf("validateSubscriptionID(%q) error = %v, want %v", tc.id, err, pqerr.ErrInvalidID)
				}

				return
			}

			if err != nil {
				t.Fatalf("validateSubscriptionID(%q) error = %v, want nil", tc.id, err)
			}
		})
	}
}

func TestValidateCreateTopicRejectsBlankName(t *testing.T) {
	tests := map[string]struct {
		input   *CreateTopicRequest
		wantErr bool
	}{
		"nil":   {wantErr: true},
		"empty": {input: &CreateTopicRequest{}, wantErr: true},
		"space": {input: &CreateTopicRequest{TopicName: " \t"}, wantErr: true},
		"valid": {input: &CreateTopicRequest{TopicName: "events"}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateCreateTopicRequest(tc.input)
			if tc.wantErr {
				if !errors.Is(err, pqerr.ErrInvalidInput) {
					t.Fatalf("validateCreateTopicRequest(%#v) error = %v, want %v", tc.input, err, pqerr.ErrInvalidInput)
				}

				return
			}

			if err != nil {
				t.Fatalf("validateCreateTopicRequest(%#v) error = %v, want nil", tc.input, err)
			}
		})
	}
}

func TestValidateListTopicsRequest(t *testing.T) {
	tests := map[string]struct {
		input   *ListTopicsRequest
		wantErr error
	}{
		"nil": {
			wantErr: pqerr.ErrInvalidInput,
		},
		"valid": {
			input: &ListTopicsRequest{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateListTopicsRequest(tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateListTopicsRequest(%#v) error = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateDeleteTopicRequest(t *testing.T) {
	tests := map[string]struct {
		topicID string
		wantErr error
	}{
		"malformed topic": {
			topicID: "not-a-topic-id",
			wantErr: pqerr.ErrInvalidID,
		},
		"valid": {
			topicID: idkit.XID(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateDeleteTopicRequest(tc.topicID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateDeleteTopicRequest(%q) error = %v, want %v", tc.topicID, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSubscribeRequest(t *testing.T) {
	validTopicID := idkit.XID()
	tests := map[string]struct {
		topicID string
		input   *SubscribeRequest
		wantErr error
	}{
		"malformed topic": {
			topicID: "not-a-topic-id",
			input:   &SubscribeRequest{QueueID: idkit.XID()},
			wantErr: pqerr.ErrInvalidID,
		},
		"nil request": {
			topicID: validTopicID,
			wantErr: pqerr.ErrInvalidInput,
		},
		"malformed queue": {
			topicID: validTopicID,
			input:   &SubscribeRequest{QueueID: "not-a-queue-id"},
			wantErr: pqerr.ErrInvalidID,
		},
		"valid": {
			topicID: validTopicID,
			input:   &SubscribeRequest{QueueID: idkit.XID()},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateSubscribeRequest(tc.topicID, tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validateSubscribeRequest(%q, %#v) error = %v, want %v", tc.topicID, tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateUnsubscribeRequest(t *testing.T) {
	validTopicID := idkit.XID()
	tests := map[string]struct {
		topicID        string
		subscriptionID string
		wantErr        error
	}{
		"malformed topic": {
			topicID:        "not-a-topic-id",
			subscriptionID: idkit.XID(),
			wantErr:        pqerr.ErrInvalidID,
		},
		"malformed subscription": {
			topicID:        validTopicID,
			subscriptionID: "not-a-subscription-id",
			wantErr:        pqerr.ErrInvalidID,
		},
		"valid": {
			topicID:        validTopicID,
			subscriptionID: idkit.XID(),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateUnsubscribeRequest(tc.topicID, tc.subscriptionID)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf(
					"validateUnsubscribeRequest(%q, %q) error = %v, want %v",
					tc.topicID,
					tc.subscriptionID,
					err,
					tc.wantErr,
				)
			}
		})
	}
}

func TestValidatePublishRejectsEmptyBatch(t *testing.T) {
	topicID := idkit.XID()
	tests := map[string]struct {
		topicID string
		input   *PublishRequest
		wantErr error
	}{
		"nil": {
			topicID: topicID,
			wantErr: pqerr.ErrInvalidInput,
		},
		"empty batch": {
			topicID: topicID,
			input:   &PublishRequest{},
			wantErr: pqerr.ErrInvalidInput,
		},
		"invalid topic": {
			topicID: "not-a-topic-id",
			input:   &PublishRequest{Messages: []PublishMessage{{}}},
			wantErr: pqerr.ErrInvalidID,
		},
		"empty body is valid": {
			topicID: topicID,
			input:   &PublishRequest{Messages: []PublishMessage{{}}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := validatePublishRequest(tc.topicID, tc.input)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("validatePublishRequest(%q, %#v) error = %v, want %v", tc.topicID, tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestPubSubQueueValidationNormalizesMalformedID(t *testing.T) {
	topicID := idkit.XID()
	tests := map[string]func() error{
		"subscribe": func() error {
			return validateSubscribeRequest(topicID, &SubscribeRequest{QueueID: "not-an-xid"})
		},
		"delete queue": func() error {
			return validatePubSubQueueID("not-an-xid")
		},
	}

	for name, validate := range tests {
		t.Run(name, func(t *testing.T) {
			err := validate()
			if !errors.Is(err, pqerr.ErrInvalidID) {
				t.Fatalf("validation error = %v, want %v", err, pqerr.ErrInvalidID)
			}
			if errors.Is(err, errkit.ErrInvalidID) {
				t.Fatalf("validation error = %v leaked legacy %v", err, errkit.ErrInvalidID)
			}
		})
	}
}
