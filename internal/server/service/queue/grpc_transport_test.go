package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/maxatome/go-testdeep/td"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_1(t *testing.T) {
	r := &v1.DescribeQueueResponse{
		QueueId:                  "UD",
		QueueName:                "Nme",
		CreatedAt:                timestamppb.New(time.Now()),
		RetentionPeriodSeconds:   60,
		VisibilityTimeoutSeconds: 30,
		MaxReceiveAttempts:       5,
		EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
		DeadLetterQueueId:        "ID",
	}

	jsonout, err := json.Marshal(r)
	td.CmpNoError(t, err)

	t.Log("jsonoutgfh", string(jsonout))
}

func TestServer_ListQueues(t *testing.T) {
	type tcase struct {
		storage *mockStorage
		req     *v1.ListQueuesRequest

		want    *v1.ListQueuesResponse
		wantErr error
	}

	tests := map[string]tcase{
		"OK": {
			storage: &mockStorage{
				listQueuesFunc: func(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
					output := v1.ListQueuesResponse{
						Queues: []*v1.DescribeQueueResponse{
							{
								QueueId:                  "test-id",
								QueueName:                "test-name",
								CreatedAt:                timestamppb.New(time.Unix(100500, 100500)),
								RetentionPeriodSeconds:   60,
								VisibilityTimeoutSeconds: 30,
								MaxReceiveAttempts:       5,
								EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
							},
						},
					}

					return &output, nil
				},
			},

			req: &v1.ListQueuesRequest{},

			want: &v1.ListQueuesResponse{
				Queues: []*v1.DescribeQueueResponse{
					{
						QueueId:                  "test-id",
						QueueName:                "test-name",
						CreatedAt:                timestamppb.New(time.Unix(100500, 100500)),
						RetentionPeriodSeconds:   60,
						VisibilityTimeoutSeconds: 30,
						MaxReceiveAttempts:       5,
						EvictionPolicy:           v1.EvictionPolicy_EVICTION_POLICY_DROP,
					},
				},
			},

			wantErr: nil,
		},
		"Err": {
			storage: &mockStorage{
				listQueuesFunc: func(ctx context.Context, input *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
					return nil, errors.New("test error")
				},
			},
			req:     &v1.ListQueuesRequest{},
			want:    nil,
			wantErr: status.Error(codes.Internal, codes.Internal.String()),
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			server := &Service{
				storage: tc.storage,
			}

			res, err := server.ListQueues(context.Background(), tc.req)
			td.CmpErrorIs(t, err, tc.wantErr)
			if tc.wantErr == nil {
				td.Cmp(t, res, tc.want)
			}
		})
	}

}
