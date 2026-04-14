package queue

import (
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
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
			wantErr: pqerr.ErrInvalidID,
		},

		"SendRequest": {
			input:   &v1.SendRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"SendRequest_err": {
			input:   &v1.SendRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
		},

		"ReceiveRequest": {
			input:   &v1.ReceiveRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"ReceiveRequest_err": {
			input:   &v1.ReceiveRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
		},

		"DeleteRequest": {
			input:   &v1.DeleteRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DeleteRequest_err": {
			input:   &v1.DeleteRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
		},

		"DescribeQueueRequest": {
			input:   &v1.DescribeQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DescribeQueueRequest_err": {
			input:   &v1.DescribeQueueRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
		},

		"DeleteQueueRequest": {
			input:   &v1.DeleteQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"DeleteQueueRequest_err": {
			input:   &v1.DeleteQueueRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
		},

		"PurgeQueueRequest": {
			input:   &v1.PurgeQueueRequest{QueueId: idkit.XID()},
			wantErr: nil,
		},

		"PurgeQueueRequest_err": {
			input:   &v1.PurgeQueueRequest{QueueId: "invalid-id"},
			wantErr: pqerr.ErrInvalidID,
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
		td.CmpErrorIs(t, err, pqerr.ErrInvalidID)
	})

	t.Run("Empty", func(t *testing.T) {
		err := validateQueueID("")
		td.CmpErrorIs(t, err, pqerr.ErrInvalidID)
	})
}
