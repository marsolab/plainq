package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"github.com/marsolab/plainq/internal/server/authz"
	"github.com/marsolab/plainq/internal/server/policytx"
	"github.com/marsolab/plainq/internal/server/principal"
	"github.com/marsolab/plainq/internal/server/service/securityaudit"
)

const maxPolicyIdempotencyKeyBytes = 128

func (s *Service) mutationFor(
	ctx context.Context,
	p principal.Principal,
	action authz.Action,
	resource authz.Resource,
	request proto.Message,
	now time.Time,
	auditMetadata map[string]string,
) (policytx.Mutation, error) {
	if request == nil {
		return policytx.Mutation{}, errors.New("policy request is required")
	}

	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return policytx.Mutation{}, fmt.Errorf("encode policy request: %w", err)
	}

	requestHash := policyDigest(
		[]byte(action), []byte(p.TenantID), []byte(p.Kind), []byte(p.ID), encoded,
	)

	idempotencyKey, err := s.policyIdempotencyKey(ctx)
	if err != nil {
		return policytx.Mutation{}, err
	}

	eventHash := policyDigest(
		[]byte(p.TenantID), []byte(p.Kind), []byte(p.ID), []byte(action), []byte(idempotencyKey),
	)
	eventID := hex.EncodeToString(eventHash[:])

	requestID, userAgent := policyRequestMetadata(ctx)

	return policytx.Mutation{
		TenantID:       p.TenantID,
		Actor:          p.Ref(),
		Action:         action,
		Resource:       resource,
		IdempotencyKey: idempotencyKey,
		RequestHash:    requestHash,
		RateUnits:      1,
		Audit: securityaudit.Event{
			EventID: eventID, TenantID: p.TenantID, ActorKind: p.Kind, ActorID: p.ID,
			Action: string(action), ResourceType: string(resource.Type), ResourceID: resource.ID,
			Outcome: "success", RequestID: requestID, SourceIP: sourceIP(ctx), UserAgent: userAgent,
			Metadata: auditMetadata, CreatedAt: now.UTC(),
		},
	}, nil
}

// bindMutationToGeneratedSecret makes retrying one-time secret issuance fail
// closed instead of replaying a stored credential record while returning fresh
// secret material that does not match it. The generated identifier is never
// persisted in audit metadata.
func bindMutationToGeneratedSecret(mutation policytx.Mutation, generatedID string) policytx.Mutation {
	mutation.RequestHash = policyDigest(mutation.RequestHash[:], []byte(generatedID))

	return mutation
}

func policyDigest(parts ...[]byte) [sha256.Size]byte {
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

func (s *Service) policyIdempotencyKey(ctx context.Context) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	keys := append([]string(nil), md.Get("idempotency-key")...)

	keys = append(keys, md.Get("x-idempotency-key")...)
	if len(keys) > 1 {
		return "", invalidInput("exactly one idempotency key is allowed")
	}

	if len(keys) == 0 {
		key := s.nextMutationID()
		if key == "" {
			return "", errors.New("generated policy idempotency key is empty")
		}

		return key, nil
	}

	key := strings.TrimSpace(keys[0])
	if key == "" || len(key) > maxPolicyIdempotencyKeyBytes {
		return "", invalidInput("idempotency key must contain 1 to 128 bytes")
	}

	return key, nil
}

//nolint:gocritic // The paired metadata values are self-explanatory at every call site.
func policyRequestMetadata(ctx context.Context) (string, string) {
	md, _ := metadata.FromIncomingContext(ctx)

	return firstMetadataValue(md, "x-request-id"), firstMetadataValue(md, "user-agent")
}

func firstMetadataValue(md metadata.MD, key string) string {
	values := md.Get(key)
	if len(values) == 0 {
		return ""
	}

	return values[0]
}
