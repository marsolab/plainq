package schema_test

import (
	"bytes"
	"testing"

	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestAgentFirstContractCompiles(t *testing.T) {
	_ = agentv1.NewAgentServiceClient
	_ = agentv1.NewPubSubServiceClient
	_ = agentv1.NewSystemServiceClient
	_ = (&v1.ReceiveMessage{}).GetReceiptHandle
	_ = (&agentv1.AgentDelivery{}).GetDeliveryAttempt
	_ = (&agentv1.SubscriptionDelivery{}).GetTopicOffset
	_ = (&agentv1.ListAgentSubscriptionsRequest{}).GetAgentId
	_ = (&agentv1.ListAgentDeadLettersRequest{}).GetAgentId
	_ = (&agentv1.ReplayAgentDeadLetterRequest{}).GetAgentId
	_ = (&v1.AcknowledgeQueueRequest{}).GetReceipts
	_ = (&v1.NackQueueRequest{}).GetDeliveries
	_ = (&v1.ExtendQueueLeaseRequest{}).GetDeliveries
	methods := map[string]bool{}
	for _, method := range agentv1.AgentService_ServiceDesc.Methods {
		methods[method.MethodName] = true
	}
	for _, name := range []string{"CreateGrant", "ListGrants", "DeleteGrant"} {
		if !methods[name] {
			t.Errorf("missing AgentService method %s", name)
		}
	}
}

func TestLegacyServiceDoesNotDeclareSafeQueueRPCsBeforeImplementations(t *testing.T) {
	methods := map[string]bool{}
	for _, method := range v1.PlainQService_ServiceDesc.Methods {
		methods[method.MethodName] = true
	}
	for _, name := range []string{"AcknowledgeQueue", "NackQueue", "ExtendQueueLease"} {
		if methods[name] {
			t.Errorf("legacy PlainQService declares %s before its implementation", name)
		}
	}
}

func TestLegacySendRequestWireCompatibility(t *testing.T) {
	legacy := []byte{0x0a, 0x01, 'q', 0x12, 0x03, 0x0a, 0x01, 'x'}
	var got v1.SendRequest
	if err := proto.Unmarshal(legacy, &got); err != nil {
		t.Fatal(err)
	}
	if got.GetQueueId() != "q" {
		t.Errorf("queue_id = %q, want q", got.GetQueueId())
	}
	if len(got.GetMessages()) != 1 || !bytes.Equal(got.GetMessages()[0].GetBody(), []byte("x")) {
		t.Errorf("messages = %v, want one message with body x", got.GetMessages())
	}
}

func TestContractFieldNumbers(t *testing.T) {
	tests := []struct {
		name   string
		fields protoreflect.FieldDescriptors
		want   map[protoreflect.Name]protoreflect.FieldNumber
	}{
		{
			name:   "legacy SendRequest",
			fields: (&v1.SendRequest{}).ProtoReflect().Descriptor().Fields(),
			want:   map[protoreflect.Name]protoreflect.FieldNumber{"queue_id": 1, "messages": 2},
		},
		{
			name:   "legacy ReceiveMessage",
			fields: (&v1.ReceiveMessage{}).ProtoReflect().Descriptor().Fields(),
			want: map[protoreflect.Name]protoreflect.FieldNumber{
				"id": 1, "body": 2, "receipt_handle": 3, "delivery_attempt": 4, "lease_expires_at": 5,
			},
		},
		{
			name:   "AgentDelivery",
			fields: (&agentv1.AgentDelivery{}).ProtoReflect().Descriptor().Fields(),
			want: map[protoreflect.Name]protoreflect.FieldNumber{
				"delivery_id": 1, "source": 2, "message": 3, "receipt_handle": 4, "delivery_attempt": 5,
				"lease_expires_at": 6, "topic_id": 7, "subscription_id": 8, "topic_offset": 9,
			},
		},
		{
			name:   "SubscriptionDelivery",
			fields: (&agentv1.SubscriptionDelivery{}).ProtoReflect().Descriptor().Fields(),
			want: map[protoreflect.Name]protoreflect.FieldNumber{
				"delivery_id": 1, "message": 2, "receipt_handle": 3, "delivery_attempt": 4,
				"lease_expires_at": 5, "topic_id": 6, "subscription_id": 7, "topic_offset": 8,
			},
		},
		{
			name:   "GetCapabilitiesResponse",
			fields: (&agentv1.GetCapabilitiesResponse{}).ProtoReflect().Descriptor().Fields(),
			want: map[protoreflect.Name]protoreflect.FieldNumber{
				"server_version": 1, "legacy_unsafe_delete_enabled": 32,
				"direct_dead_letter_retention_seconds": 33, "security_audit_retention_seconds": 34,
				"legacy_v1_auth_required": 35, "agent_messaging_feature_active": 36,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for name, want := range tt.want {
				field := tt.fields.ByName(name)
				if field == nil {
					t.Errorf("missing field %s", name)
					continue
				}
				if got := field.Number(); got != want {
					t.Errorf("field %s number = %d, want %d", name, got, want)
				}
			}
		})
	}
}

func TestServiceDescriptorsUseUniqueStandardRequestResponseNames(t *testing.T) {
	services := agentv1.File_agent_v1_messaging_proto.Services()
	wantMethodCounts := map[protoreflect.Name]int{
		"AgentService":  23,
		"PubSubService": 15,
		"SystemService": 1,
	}
	inputNames := map[protoreflect.FullName]protoreflect.FullName{}
	outputNames := map[protoreflect.FullName]protoreflect.FullName{}

	for serviceName, wantCount := range wantMethodCounts {
		service := services.ByName(serviceName)
		if service == nil {
			t.Errorf("missing service %s", serviceName)
			continue
		}
		if got := service.Methods().Len(); got != wantCount {
			t.Errorf("%s method count = %d, want %d", serviceName, got, wantCount)
		}
		for i := 0; i < service.Methods().Len(); i++ {
			method := service.Methods().Get(i)
			wantInput := protoreflect.Name(string(method.Name()) + "Request")
			wantOutput := protoreflect.Name(string(method.Name()) + "Response")
			if method.Input().Name() != wantInput {
				t.Errorf("%s input = %s, want %s", method.FullName(), method.Input().Name(), wantInput)
			}
			if method.Output().Name() != wantOutput {
				t.Errorf("%s output = %s, want %s", method.FullName(), method.Output().Name(), wantOutput)
			}
			if previous, exists := inputNames[method.Input().FullName()]; exists {
				t.Errorf("input %s shared by %s and %s", method.Input().FullName(), previous, method.FullName())
			}
			if previous, exists := outputNames[method.Output().FullName()]; exists {
				t.Errorf("output %s shared by %s and %s", method.Output().FullName(), previous, method.FullName())
			}
			inputNames[method.Input().FullName()] = method.FullName()
			outputNames[method.Output().FullName()] = method.FullName()

			wantServerStreaming := method.Name() == "ListenInbox" || method.Name() == "ListenSubscription"
			if method.IsStreamingServer() != wantServerStreaming {
				t.Errorf("%s server streaming = %t, want %t", method.FullName(), method.IsStreamingServer(), wantServerStreaming)
			}
			if method.IsStreamingClient() {
				t.Errorf("%s unexpectedly client streaming", method.FullName())
			}
		}
	}
}
