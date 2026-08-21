package queue

import (
	"context"
	"fmt"

	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

type legacyV1Authorization uint8

const (
	legacyV1TenantAdmin legacyV1Authorization = iota + 1
	legacyV1QueuePermission
)

type legacyV1Policy struct {
	authorization legacyV1Authorization
	permission    middleware.PermissionType
	requireTopic  bool
	requireQueue  bool
}

// legacyV1Policies is an explicit authorization inventory for every generated
// schema.v1 RPC. The generated-descriptor regression fails if either side gains
// a method without a deliberate policy decision.
var legacyV1Policies = map[string]legacyV1Policy{
	v1.PlainQService_ListQueues_FullMethodName: {
		authorization: legacyV1TenantAdmin,
	},
	v1.PlainQService_DescribeQueue_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionReceive, requireQueue: true,
	},
	v1.PlainQService_CreateQueue_FullMethodName: {
		authorization: legacyV1TenantAdmin,
	},
	v1.PlainQService_PurgeQueue_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionPurge, requireQueue: true,
	},
	v1.PlainQService_DeleteQueue_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionDelete, requireQueue: true,
	},
	v1.PlainQService_Send_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionSend, requireQueue: true,
	},
	v1.PlainQService_Receive_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionReceive, requireQueue: true,
	},
	v1.PlainQService_Delete_FullMethodName: {
		authorization: legacyV1QueuePermission, permission: middleware.PermissionDelete, requireQueue: true,
	},
	v1.PlainQService_ListTopics_FullMethodName: {
		authorization: legacyV1TenantAdmin,
	},
	v1.PlainQService_CreateTopic_FullMethodName: {
		authorization: legacyV1TenantAdmin,
	},
	v1.PlainQService_DeleteTopic_FullMethodName: {
		authorization: legacyV1TenantAdmin, requireTopic: true,
	},
	v1.PlainQService_Subscribe_FullMethodName: {
		authorization: legacyV1TenantAdmin, requireTopic: true, requireQueue: true,
	},
	v1.PlainQService_Unsubscribe_FullMethodName: {
		authorization: legacyV1TenantAdmin, requireTopic: true,
	},
	v1.PlainQService_Publish_FullMethodName: {
		authorization: legacyV1TenantAdmin, requireTopic: true,
	},
}

type legacyV1Resource struct {
	queueID   string
	queueName string
	topicID   string
}

//nolint:cyclop // Every generated legacy method remains visible in one fail-closed policy dispatcher.
func (s *Service) authorizeProtectedLegacyRPC(
	ctx context.Context,
	method string,
	resource legacyV1Resource,
) error {
	if s.cfg == nil || !s.cfg.GRPCProtectLegacy {
		return nil
	}

	p, err := principal.Require(ctx)
	if err != nil {
		return fmt.Errorf("%w: authenticated principal is required", pqerr.ErrUnauthenticated)
	}

	policy, ok := legacyV1Policies[method]
	if !ok || policy.authorization == 0 {
		return fmt.Errorf("%w: legacy RPC has no authorization policy", pqerr.ErrUnauthorized)
	}

	if policy.requireTopic {
		if err := s.requireLegacyTopicInTenant(ctx, resource.topicID); err != nil {
			return err
		}
	}

	resolvedQueueID := resource.queueID
	if policy.requireQueue {
		resolved, err := s.requireLegacyQueueInTenant(ctx, resource.queueID, resource.queueName)
		if err != nil {
			return err
		}

		resolvedQueueID = resolved
	}

	switch policy.authorization {
	case legacyV1TenantAdmin:
		if !p.HasRole("admin") {
			return pqerr.ErrUnauthorized
		}

		return nil

	case legacyV1QueuePermission:
		allowed, err := s.HasQueuePermission(ctx, p.ID, resolvedQueueID, policy.permission)
		if err != nil {
			return err
		}

		if !allowed {
			return pqerr.ErrUnauthorized
		}

		return nil

	default:
		return fmt.Errorf("%w: invalid legacy RPC authorization policy", pqerr.ErrUnauthorized)
	}
}

func (s *Service) requireLegacyQueueInTenant(ctx context.Context, queueID, queueName string) (string, error) {
	if queueID == "" && queueName == "" {
		return "", fmt.Errorf("%w: queue ID or name is required", pqerr.ErrInvalidInput)
	}

	queue, err := s.storage.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID, QueueName: queueName})
	if err != nil {
		return "", fmt.Errorf("resolve protected legacy queue: %w", err)
	}

	if queue == nil || queue.GetQueueId() == "" {
		return "", fmt.Errorf("resolve protected legacy queue: %w", pqerr.ErrNotFound)
	}

	return queue.GetQueueId(), nil
}

func (s *Service) requireLegacyTopicInTenant(ctx context.Context, topicID string) error {
	if topicID == "" {
		return fmt.Errorf("%w: topic ID is required", pqerr.ErrInvalidInput)
	}

	topics, err := s.storage.ListTopics(ctx)
	if err != nil {
		return fmt.Errorf("list protected legacy topics: %w", err)
	}

	for _, topic := range topics.Topics {
		if topic.TopicID == topicID {
			return nil
		}
	}

	return fmt.Errorf("resolve protected legacy topic: %w", pqerr.ErrNotFound)
}
