package server

import (
	"context"

	"github.com/plainq/plainq/internal/server/auth"
	"github.com/plainq/plainq/internal/server/interceptor"
	v1 "github.com/plainq/plainq/internal/server/schema/v1"
	"github.com/plainq/servekit/respond"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *PlainQ) ListQueues(
	ctx context.Context,
	r *v1.ListQueuesRequest,
) (*v1.ListQueuesResponse, error) {
	output, listErr := s.storage.ListQueues(ctx, r)
	if listErr != nil {
		return respond.ErrorGRPC[*v1.ListQueuesResponse](ctx, listErr)
	}

	return output, nil
}

func (s *PlainQ) DescribeQueue(
	ctx context.Context,
	r *v1.DescribeQueueRequest,
) (*v1.DescribeQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.DescribeQueueResponse](ctx, err)
	}

	output, createErr := s.storage.DescribeQueue(ctx, r)
	if createErr != nil {
		return respond.ErrorGRPC[*v1.DescribeQueueResponse](ctx, createErr)
	}

	return output, nil
}

func (s *PlainQ) CreateQueue(ctx context.Context, r *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	// Queue creation requires admin role.
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok || !auth.IsAdmin(claims.Roles) {
			return nil, status.Error(codes.PermissionDenied, "admin role required to create queues")
		}
	}

	output, createErr := s.storage.CreateQueue(ctx, r)
	if createErr != nil {
		return respond.ErrorGRPC[*v1.CreateQueueResponse](ctx, createErr)
	}

	return output, nil
}

func (s *PlainQ) DeleteQueue(ctx context.Context, r *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.DeleteQueueResponse](ctx, err)
	}

	// Check delete permission.
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		if err := s.permissionService.CheckQueuePermission(ctx, r.QueueId, claims.Roles, auth.ActionDelete); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}

	if _, err := s.storage.DeleteQueue(ctx, r); err != nil {
		return respond.ErrorGRPC[*v1.DeleteQueueResponse](ctx, err)
	}

	return &v1.DeleteQueueResponse{}, nil
}

func (s *PlainQ) PurgeQueue(ctx context.Context, r *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.PurgeQueueResponse](ctx, err)
	}

	// Check purge permission.
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		if err := s.permissionService.CheckQueuePermission(ctx, r.QueueId, claims.Roles, auth.ActionPurge); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}

	output, purgeErr := s.storage.PurgeQueue(ctx, r)
	if purgeErr != nil {
		return respond.ErrorGRPC[*v1.PurgeQueueResponse](ctx, purgeErr)
	}

	return output, nil
}

func (s *PlainQ) Send(ctx context.Context, r *v1.SendRequest) (*v1.SendResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.SendResponse](ctx, err)
	}

	// Check send permission.
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		if err := s.permissionService.CheckQueuePermission(ctx, r.QueueId, claims.Roles, auth.ActionSend); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}

	output, sendErr := s.storage.Send(ctx, r)
	if sendErr != nil {
		return respond.ErrorGRPC[*v1.SendResponse](ctx, sendErr)
	}

	return output, nil
}

func (s *PlainQ) Receive(ctx context.Context, r *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.ReceiveResponse](ctx, err)
	}

	// Check receive permission.
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		if err := s.permissionService.CheckQueuePermission(ctx, r.QueueId, claims.Roles, auth.ActionReceive); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}

	output, receiveErr := s.storage.Receive(ctx, r)
	if receiveErr != nil {
		return respond.ErrorGRPC[*v1.ReceiveResponse](ctx, receiveErr)
	}

	return output, nil
}

func (s *PlainQ) Delete(ctx context.Context, r *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	if err := validateQueueIDFromRequest(r); err != nil {
		return respond.ErrorGRPC[*v1.DeleteResponse](ctx, err)
	}

	// Check receive permission (delete message requires receive permission).
	if s.permissionService != nil {
		claims, ok := interceptor.GetClaimsFromContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}
		if err := s.permissionService.CheckQueuePermission(ctx, r.QueueId, claims.Roles, auth.ActionReceive); err != nil {
			return nil, status.Error(codes.PermissionDenied, err.Error())
		}
	}

	output, deleteErr := s.storage.Delete(ctx, r)
	if deleteErr != nil {
		return respond.ErrorGRPC[*v1.DeleteResponse](ctx, deleteErr)
	}

	return output, nil
}
