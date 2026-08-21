//nolint:wrapcheck // This application boundary intentionally preserves typed authorization, quota, and storage errors.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/marsolab/servekit/idkit"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/middleware"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

const (
	maxOperationIdempotencyKeyBytes = 128
	auditMetadataMessageCount       = "message_count"
)

// PolicyStorage is the transaction-aware legacy queue backend seam. Task 15
// carries the same envelope through Raft; Task 8 deliberately keeps that
// replication change out of the local SQLite/PostgreSQL implementation.
//
//nolint:interfacebloat // One transaction-aware seam keeps every legacy operation on the same policy envelope.
type PolicyStorage interface {
	ResolveQueueResource(ctx context.Context, tenantID, queueID, queueName string) (authz.Resource, error)
	ResolveTopicResource(ctx context.Context, tenantID, topicID string) (authz.Resource, error)
	ResolveSubscriptionResource(
		ctx context.Context,
		tenantID, topicID, subscriptionID string,
	) (authz.Resource, error)

	CreateQueuePolicy(
		ctx context.Context,
		input *v1.CreateQueueRequest,
		mutation policytx.Mutation,
	) (*v1.CreateQueueResponse, error)
	PurgeQueuePolicy(
		ctx context.Context,
		input *v1.PurgeQueueRequest,
		mutation policytx.Mutation,
	) (*v1.PurgeQueueResponse, error)
	DeleteQueuePolicy(
		ctx context.Context,
		input *v1.DeleteQueueRequest,
		mutation policytx.Mutation,
	) (*v1.DeleteQueueResponse, error)
	SendPolicy(ctx context.Context, input *v1.SendRequest, mutation policytx.Mutation) (*v1.SendResponse, error)
	ReceivePolicy(
		ctx context.Context,
		input *v1.ReceiveRequest,
		mutation policytx.Mutation,
	) (*v1.ReceiveResponse, error)
	DeletePolicy(ctx context.Context, input *v1.DeleteRequest, mutation policytx.Mutation) (*v1.DeleteResponse, error)
	CreateTopicPolicy(
		ctx context.Context,
		input *CreateTopicRequest,
		mutation policytx.Mutation,
	) (*CreateTopicResponse, error)
	DeleteTopicPolicy(ctx context.Context, topicID string, mutation policytx.Mutation) error
	SubscribePolicy(
		ctx context.Context,
		topicID string,
		input *SubscribeRequest,
		mutation policytx.Mutation,
	) (*SubscribeResponse, error)
	UnsubscribePolicy(ctx context.Context, topicID, subscriptionID string, mutation policytx.Mutation) error
	PublishPolicy(
		ctx context.Context,
		topicID string,
		input *PublishRequest,
		mutation policytx.Mutation,
	) (*PublishResponse, error)

	AppendReadAudit(ctx context.Context, event securityaudit.Event) error
}

// Operations is the single application-policy path shared by HTTP and gRPC.
// Transports validate their wire shape and delegate here; they never resolve a
// tenant resource or call mutation storage directly.
type Operations struct {
	store       Storage
	policyStore PolicyStorage
	authorizer  authz.Authorizer
	clock       func() time.Time
	nextID      func() string
}

// NewOperations constructs the shared queue policy layer. A nil authorizer is
// accepted only for the explicit anonymous legacy compatibility identity; all
// authenticated callers then fail closed.
func NewOperations(store Storage, authorizer authz.Authorizer) (*Operations, error) {
	if store == nil {
		return nil, errors.New("queue storage is required")
	}

	policyStore, ok := store.(PolicyStorage)
	if !ok {
		policyStore = nil
	}

	if authorizer == nil {
		if policies, ok := store.(authz.PolicyStore); ok {
			var err error

			authorizer, err = authz.NewAuthorizer(policies)
			if err != nil {
				return nil, fmt.Errorf("create queue authorizer: %w", err)
			}
		}
	}

	return &Operations{
		store: store, policyStore: policyStore, authorizer: authorizer,
		clock: time.Now, nextID: idkit.ULID,
	}, nil
}

func (o *Operations) ListQueues(ctx context.Context, req *v1.ListQueuesRequest) (*v1.ListQueuesResponse, error) {
	p := operationPrincipal(ctx)

	resource := tenantResource(p.TenantID)
	if err := o.authorize(ctx, p, authz.ActionQueueRead, resource); err != nil {
		return nil, err
	}

	response, err := o.store.ListQueues(ctx, req)
	if err == nil {
		o.auditRead(ctx, p, authz.ActionQueueRead, resource, nil)
	}

	return response, err
}

func (o *Operations) DescribeQueue(ctx context.Context, req *v1.DescribeQueueRequest) (*v1.DescribeQueueResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.DescribeQueue(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), req.GetQueueName())
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueRead, resource); err != nil {
		return nil, err
	}

	response, err := o.store.DescribeQueue(ctx, req)
	if err == nil {
		o.auditRead(ctx, p, authz.ActionQueueRead, resource, nil)
	}

	return response, err
}

func (o *Operations) Peek(ctx context.Context, req *PeekRequest) (*PeekResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Peek(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.QueueID, "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueRead, resource); err != nil {
		return nil, err
	}

	response, err := o.store.Peek(ctx, req)
	if err == nil {
		o.auditRead(ctx, p, authz.ActionQueueRead, resource, map[string]string{"batch_size": strconv.Itoa(len(response.Messages))})
	}

	return response, err
}

func (o *Operations) CreateQueue(ctx context.Context, req *v1.CreateQueueRequest) (*v1.CreateQueueResponse, error) {
	p := operationPrincipal(ctx)

	resource := tenantResource(p.TenantID)
	if err := o.authorize(ctx, p, authz.ActionQueueCreate, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionQueueCreate, resource, req, 1, nil)
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatCreateQueue(ctx, p, req)
	}

	return o.policyStore.CreateQueuePolicy(ctx, req, mutation)
}

func (o *Operations) PurgeQueue(ctx context.Context, req *v1.PurgeQueueRequest) (*v1.PurgeQueueResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.PurgeQueue(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueuePurge, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionQueuePurge, resource, req, 1, nil)
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatPurgeQueue(ctx, p, req)
	}

	return o.policyStore.PurgeQueuePolicy(ctx, req, mutation)
}

func (o *Operations) DeleteQueue(ctx context.Context, req *v1.DeleteQueueRequest) (*v1.DeleteQueueResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.DeleteQueue(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueDelete, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionQueueDelete, resource, req, 1, nil)
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatDeleteQueue(ctx, p, req)
	}

	return o.policyStore.DeleteQueuePolicy(ctx, req, mutation)
}

func (o *Operations) Send(ctx context.Context, req *v1.SendRequest) (*v1.SendResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Send(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueSend, resource); err != nil {
		return nil, err
	}

	units := max(uint64(len(req.GetMessages())), 1)

	mutation, err := o.mutation(ctx, p, authz.ActionQueueSend, resource, req, units,
		map[string]string{auditMetadataMessageCount: strconv.Itoa(len(req.GetMessages()))})
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatSend(ctx, p, req)
	}

	return o.policyStore.SendPolicy(ctx, req, mutation)
}

func (o *Operations) Receive(ctx context.Context, req *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Receive(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueReceive, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionQueueReceive, resource, req, 1,
		map[string]string{"batch_size": strconv.FormatUint(uint64(req.GetBatchSize()), 10)})
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatReceive(ctx, p, req)
	}

	return o.policyStore.ReceivePolicy(ctx, req, mutation)
}

func (o *Operations) Delete(ctx context.Context, req *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Delete(ctx, req)
	}

	resource, err := o.resolveQueue(ctx, p, req.GetQueueId(), "")
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionQueueAck, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionQueueAck, resource, req, 1,
		map[string]string{auditMetadataMessageCount: strconv.Itoa(len(req.GetMessageIds()))})
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatDelete(ctx, p, req)
	}

	return o.policyStore.DeletePolicy(ctx, req, mutation)
}

func (o *Operations) ListTopics(ctx context.Context) (*ListTopicsResponse, error) {
	p := operationPrincipal(ctx)

	resource := tenantResource(p.TenantID)
	if err := o.authorize(ctx, p, authz.ActionTopicRead, resource); err != nil {
		return nil, err
	}

	response, err := o.store.ListTopics(ctx)
	if err == nil {
		o.auditRead(ctx, p, authz.ActionTopicRead, resource, nil)
	}

	return response, err
}

func (o *Operations) CreateTopic(ctx context.Context, req *CreateTopicRequest) (*CreateTopicResponse, error) {
	p := operationPrincipal(ctx)

	resource := tenantResource(p.TenantID)
	if err := o.authorize(ctx, p, authz.ActionTopicCreate, resource); err != nil {
		return nil, err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionTopicCreate, resource, req, 1, nil)
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatCreateTopic(ctx, p, req)
	}

	return o.policyStore.CreateTopicPolicy(ctx, req, mutation)
}

func (o *Operations) DeleteTopic(ctx context.Context, topicID string) error {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.DeleteTopic(ctx, topicID)
	}

	resource, err := o.resolveTopic(ctx, p, topicID)
	if err != nil {
		return err
	}

	if err := o.authorize(ctx, p, authz.ActionTopicDelete, resource); err != nil {
		return err
	}

	mutation, err := o.mutation(ctx, p, authz.ActionTopicDelete, resource, struct {
		TopicID string `json:"topicId"`
	}{topicID}, 1, nil)
	if err != nil {
		return err
	}

	if o.policyStore == nil {
		return o.compatDeleteTopic(ctx, p, topicID)
	}

	return o.policyStore.DeleteTopicPolicy(ctx, topicID, mutation)
}

func (o *Operations) Subscribe(ctx context.Context, topicID string, req *SubscribeRequest) (*SubscribeResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Subscribe(ctx, topicID, req)
	}

	resource, err := o.resolveTopic(ctx, p, topicID)
	if err != nil {
		return nil, err
	}

	if _, err := o.resolveQueue(ctx, p, req.QueueID, ""); err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionTopicSubscribe, resource); err != nil {
		return nil, err
	}

	request := struct {
		TopicID string            `json:"topicId"`
		Input   *SubscribeRequest `json:"input"`
	}{topicID, req}

	mutation, err := o.mutation(ctx, p, authz.ActionTopicSubscribe, resource, request, 1, nil)
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatSubscribe(ctx, p, topicID, req)
	}

	return o.policyStore.SubscribePolicy(ctx, topicID, req, mutation)
}

//nolint:cyclop // Compatibility and durable paths deliberately share one authorization decision surface.
func (o *Operations) Unsubscribe(ctx context.Context, topicID, subscriptionID string) error {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Unsubscribe(ctx, topicID, subscriptionID)
	}

	if o.policyStore == nil && o.authorizer != nil {
		if o.legacyFallbackRequiresResolution() {
			if _, err := o.resolveTopic(ctx, p, topicID); err != nil {
				return err
			}
		}

		if err := o.authorizer.Authorize(ctx, p, authz.ActionSubscriptionDelete, tenantResource(p.TenantID)); err != nil {
			return err
		}

		return o.store.Unsubscribe(ctx, topicID, subscriptionID)
	}

	resource, err := o.resolveSubscription(ctx, p, topicID, subscriptionID)
	if err != nil {
		return err
	}

	if err := o.authorize(ctx, p, authz.ActionSubscriptionDelete, resource); err != nil {
		return err
	}

	request := struct {
		TopicID        string `json:"topicId"`
		SubscriptionID string `json:"subscriptionId"`
	}{topicID, subscriptionID}

	mutation, err := o.mutation(ctx, p, authz.ActionSubscriptionDelete, resource, request, 1, nil)
	if err != nil {
		return err
	}

	if o.policyStore == nil {
		return o.compatUnsubscribe(ctx, p, topicID, subscriptionID)
	}

	return o.policyStore.UnsubscribePolicy(ctx, topicID, subscriptionID, mutation)
}

func (o *Operations) Publish(ctx context.Context, topicID string, req *PublishRequest) (*PublishResponse, error) {
	p := operationPrincipal(ctx)
	if o.compatibilityOnly(p) {
		return o.store.Publish(ctx, topicID, req)
	}

	resource, err := o.resolveTopic(ctx, p, topicID)
	if err != nil {
		return nil, err
	}

	if err := o.authorize(ctx, p, authz.ActionTopicPublish, resource); err != nil {
		return nil, err
	}

	request := struct {
		TopicID string          `json:"topicId"`
		Input   *PublishRequest `json:"input"`
	}{topicID, req}
	units := max(uint64(len(req.Messages)), 1)

	mutation, err := o.mutation(ctx, p, authz.ActionTopicPublish, resource, request, units,
		map[string]string{auditMetadataMessageCount: strconv.Itoa(len(req.Messages))})
	if err != nil {
		return nil, err
	}

	if o.policyStore == nil {
		return o.compatPublish(ctx, p, topicID, req)
	}

	return o.policyStore.PublishPolicy(ctx, topicID, req, mutation)
}

func (o *Operations) resolveQueue(
	ctx context.Context,
	p principal.Principal,
	queueID, queueName string,
) (authz.Resource, error) {
	if o.policyStore != nil {
		return o.policyStore.ResolveQueueResource(ctx, p.TenantID, queueID, queueName)
	}

	if queueID != "" && !o.legacyFallbackRequiresResolution() {
		return authz.Resource{Type: authz.ResourceQueue, TenantID: p.TenantID, ID: queueID}, nil
	}

	described, err := o.store.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID, QueueName: queueName})
	if err != nil {
		return authz.Resource{}, err
	}

	return authz.Resource{Type: authz.ResourceQueue, TenantID: p.TenantID, ID: described.GetQueueId()}, nil
}

func (o *Operations) resolveTopic(
	ctx context.Context,
	p principal.Principal,
	topicID string,
) (authz.Resource, error) {
	if o.policyStore != nil {
		return o.policyStore.ResolveTopicResource(ctx, p.TenantID, topicID)
	}

	topics, err := o.store.ListTopics(ctx)
	if err != nil {
		return authz.Resource{}, err
	}

	for _, topic := range topics.Topics {
		if topic.TopicID == topicID {
			return authz.Resource{Type: authz.ResourceTopic, TenantID: p.TenantID, ID: topicID}, nil
		}
	}

	return authz.Resource{}, authz.ErrNotFound
}

func (o *Operations) resolveSubscription(
	ctx context.Context,
	p principal.Principal,
	topicID, subscriptionID string,
) (authz.Resource, error) {
	if o.policyStore != nil {
		return o.policyStore.ResolveSubscriptionResource(ctx, p.TenantID, topicID, subscriptionID)
	}

	topics, err := o.store.ListTopics(ctx)
	if err != nil {
		return authz.Resource{}, err
	}

	for _, topic := range topics.Topics {
		if topic.TopicID != topicID {
			continue
		}

		for _, subscription := range topic.Subscriptions {
			if subscription.SubscriptionID == subscriptionID {
				return authz.Resource{
					Type: authz.ResourceSubscription, TenantID: p.TenantID, ID: subscriptionID,
				}, nil
			}
		}
	}

	return authz.Resource{}, authz.ErrNotFound
}

func (o *Operations) authorize(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
) error {
	if o.authorizer != nil {
		return o.authorizer.Authorize(ctx, p, action, resource)
	}

	if p.Kind == principal.KindSystem && p.ID == principal.LegacyPrincipalID &&
		p.TenantID == principal.LegacyTenantID {
		return nil
	}

	return authz.ErrPermissionDenied
}

func (o *Operations) compatibilityOnly(p principal.Principal) bool {
	return o.policyStore == nil && o.authorizer == nil && isLegacyCompatibilityPrincipal(p)
}

func (o *Operations) legacyFallbackRequiresResolution() bool {
	authorizer, ok := o.authorizer.(legacyServicePolicyAuthorizer)

	return ok && authorizer.service.cfg != nil && authorizer.service.cfg.GRPCProtectLegacy
}

func (o *Operations) mutation(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
	request any,
	rateUnits uint64,
	auditMetadata map[string]string,
) (policytx.Mutation, error) {
	requestBytes, err := encodeOperationRequest(request)
	if err != nil {
		return policytx.Mutation{}, err
	}

	requestHash := operationDigest(
		[]byte(action), []byte(p.TenantID), []byte(p.Kind), []byte(p.ID), requestBytes,
	)

	idempotencyKey, err := o.idempotencyKey(ctx)
	if err != nil {
		return policytx.Mutation{}, err
	}

	now := WriteTime(ctx).UTC()
	if now.IsZero() {
		now = o.clock().UTC()
	}

	eventHash := sha256.Sum256([]byte(strings.Join([]string{
		p.TenantID, string(p.Kind), p.ID, string(action), idempotencyKey,
	}, "\x00")))
	requestID, sourceIP, userAgent := operationRequestMetadata(ctx)

	return policytx.Mutation{
		TenantID: p.TenantID, Actor: p.Ref(), Action: action, Resource: resource,
		IdempotencyKey: idempotencyKey, RequestHash: requestHash, RateUnits: rateUnits,
		Audit: securityaudit.Event{
			EventID: hex.EncodeToString(eventHash[:]), TenantID: p.TenantID,
			ActorKind: p.Kind, ActorID: p.ID, Action: string(action),
			ResourceType: string(resource.Type), ResourceID: resource.ID, Outcome: "success",
			RequestID: requestID, SourceIP: sourceIP, UserAgent: userAgent,
			Metadata: auditMetadata, CreatedAt: now,
		},
	}, nil
}

func (o *Operations) idempotencyKey(ctx context.Context) (string, error) {
	requestMetadata, ok := ctx.Value(operationMetadataKey{}).(operationMetadata)
	if !ok {
		requestMetadata = operationMetadata{}
	}

	keys := append([]string(nil), requestMetadata.idempotencyKeys...)
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		keys = append(keys, md.Get("idempotency-key")...)
		keys = append(keys, md.Get("x-idempotency-key")...)
	}

	if len(keys) > 1 {
		return "", errors.New("exactly one idempotency key is allowed")
	}

	if len(keys) == 0 {
		key := o.nextID()
		if key == "" {
			return "", errors.New("generated idempotency key is empty")
		}

		return key, nil
	}

	key := strings.TrimSpace(keys[0])
	if key == "" || len(key) > maxOperationIdempotencyKeyBytes {
		return "", errors.New("idempotency key must contain 1 to 128 bytes")
	}

	return key, nil
}

func (o *Operations) auditRead(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
	auditMetadata map[string]string,
) {
	if o.policyStore == nil {
		return
	}

	key := o.nextID()
	eventHash := sha256.Sum256([]byte(strings.Join([]string{
		p.TenantID, string(p.Kind), p.ID, string(action), key,
	}, "\x00")))

	requestID, sourceIP, userAgent := operationRequestMetadata(ctx)
	if err := o.policyStore.AppendReadAudit(ctx, securityaudit.Event{
		EventID: hex.EncodeToString(eventHash[:]), TenantID: p.TenantID,
		ActorKind: p.Kind, ActorID: p.ID, Action: string(action),
		ResourceType: string(resource.Type), ResourceID: resource.ID, Outcome: "success",
		RequestID: requestID, SourceIP: sourceIP, UserAgent: userAgent,
		Metadata: auditMetadata, CreatedAt: o.clock().UTC(),
	}); err != nil {
		return
	}
}

func operationDigest(parts ...[]byte) [sha256.Size]byte {
	size := max(0, len(parts)-1)
	for _, part := range parts {
		size += len(part)
	}

	payload := make([]byte, 0, size)

	for index, part := range parts {
		if index != 0 {
			payload = append(payload, 0)
		}

		payload = append(payload, part...)
	}

	return sha256.Sum256(payload)
}

func encodeOperationRequest(request any) ([]byte, error) {
	if message, ok := request.(proto.Message); ok {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("encode queue policy request: %w", err)
		}

		return encoded, nil
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode queue policy request: %w", err)
	}

	return encoded, nil
}

func operationPrincipal(ctx context.Context) principal.Principal {
	if p, ok := principal.From(ctx); ok && p.ID != "" && p.TenantID != "" {
		return p
	}

	if user, ok := ctx.Value(middleware.UserContextKey).(middleware.UserInfo); ok &&
		user.UserID != "" && user.TenantID != "" {
		return principal.Principal{
			Kind: principal.KindHuman, ID: user.UserID, TenantID: user.TenantID,
			Roles: append([]string(nil), user.Roles...),
		}
	}

	return principal.Principal{
		Kind: principal.KindSystem, ID: principal.LegacyPrincipalID, TenantID: principal.LegacyTenantID,
	}
}

func tenantResource(tenantID string) authz.Resource {
	return authz.Resource{Type: authz.ResourceTenant, TenantID: tenantID, ID: tenantID}
}

type operationMetadataKey struct{}

type operationMetadata struct {
	idempotencyKeys []string
	requestID       string
	sourceIP        string
	userAgent       string
}

// WithHTTPRequestPolicyMetadata copies bounded request metadata into the
// context without retaining a body, token, credential, or message payload.
func WithHTTPRequestPolicyMetadata(
	ctx context.Context,
	idempotencyKeys []string,
	requestID, remoteAddr, userAgent string,
) context.Context {
	sourceIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		sourceIP = host
	}

	return context.WithValue(ctx, operationMetadataKey{}, operationMetadata{
		idempotencyKeys: append([]string(nil), idempotencyKeys...),
		requestID:       requestID, sourceIP: sourceIP, userAgent: userAgent,
	})
}

//nolint:gocritic // Request ID, source IP, and user agent are a compact transport metadata tuple.
func operationRequestMetadata(ctx context.Context) (string, string, string) {
	if values, ok := ctx.Value(operationMetadataKey{}).(operationMetadata); ok {
		return values.requestID, values.sourceIP, values.userAgent
	}

	md, _ := metadata.FromIncomingContext(ctx)

	return firstOperationMetadata(md, "x-request-id"), "", firstOperationMetadata(md, "user-agent")
}

func firstOperationMetadata(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func isLegacyCompatibilityPrincipal(p principal.Principal) bool {
	return p.Kind == principal.KindSystem && p.ID == principal.LegacyPrincipalID &&
		p.TenantID == principal.LegacyTenantID
}

func (o *Operations) compatCreateQueue(
	ctx context.Context,
	p principal.Principal,
	req *v1.CreateQueueRequest,
) (*v1.CreateQueueResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.CreateQueue(ctx, req)
}

func (o *Operations) compatPurgeQueue(
	ctx context.Context,
	p principal.Principal,
	req *v1.PurgeQueueRequest,
) (*v1.PurgeQueueResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.PurgeQueue(ctx, req)
}

func (o *Operations) compatDeleteQueue(
	ctx context.Context,
	p principal.Principal,
	req *v1.DeleteQueueRequest,
) (*v1.DeleteQueueResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.DeleteQueue(ctx, req)
}
func (o *Operations) compatSend(ctx context.Context, p principal.Principal, req *v1.SendRequest) (*v1.SendResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.Send(ctx, req)
}
func (o *Operations) compatReceive(ctx context.Context, p principal.Principal, req *v1.ReceiveRequest) (*v1.ReceiveResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.Receive(ctx, req)
}
func (o *Operations) compatDelete(ctx context.Context, p principal.Principal, req *v1.DeleteRequest) (*v1.DeleteResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.Delete(ctx, req)
}
func (o *Operations) compatCreateTopic(ctx context.Context, p principal.Principal, req *CreateTopicRequest) (*CreateTopicResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.CreateTopic(ctx, req)
}
func (o *Operations) compatDeleteTopic(ctx context.Context, p principal.Principal, topicID string) error {
	if !o.canUseLegacyStore(p) {
		return authz.ErrPermissionDenied
	}

	return o.store.DeleteTopic(ctx, topicID)
}

func (o *Operations) compatSubscribe(
	ctx context.Context,
	p principal.Principal,
	topicID string,
	req *SubscribeRequest,
) (*SubscribeResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.Subscribe(ctx, topicID, req)
}
func (o *Operations) compatUnsubscribe(ctx context.Context, p principal.Principal, topicID, subscriptionID string) error {
	if !o.canUseLegacyStore(p) {
		return authz.ErrPermissionDenied
	}

	return o.store.Unsubscribe(ctx, topicID, subscriptionID)
}

func (o *Operations) compatPublish(
	ctx context.Context,
	p principal.Principal,
	topicID string,
	req *PublishRequest,
) (*PublishResponse, error) {
	if !o.canUseLegacyStore(p) {
		return nil, authz.ErrPermissionDenied
	}

	return o.store.Publish(ctx, topicID, req)
}

func (o *Operations) canUseLegacyStore(p principal.Principal) bool {
	return o.policyStore == nil && (o.authorizer != nil || isLegacyCompatibilityPrincipal(p))
}
