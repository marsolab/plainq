package v1

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestStablePubSubDescriptor(t *testing.T) {
	t.Parallel()

	service := File_v1_schema_proto.Services().ByName("PlainQService")
	if service == nil {
		t.Fatal("PlainQService descriptor is missing")
	}

	methods := map[protoreflect.Name]bool{
		"ListTopics":  false,
		"CreateTopic": false,
		"DeleteTopic": false,
		"Subscribe":   false,
		"Unsubscribe": false,
		"Publish":     false,
	}
	for name := range methods {
		methods[name] = service.Methods().ByName(name) != nil
	}
	for name, found := range methods {
		if !found {
			t.Errorf("stable method %s is missing", name)
		}
	}

	fields := map[protoreflect.Name]map[protoreflect.Name]protoreflect.FieldNumber{
		"Topic":               {"topic_id": 1, "topic_name": 2, "created_at": 3, "subscriptions": 4},
		"Subscription":        {"subscription_id": 1, "topic_id": 2, "queue_id": 3, "queue_name": 4, "created_at": 5},
		"ListTopicsResponse":  {"topics": 1},
		"CreateTopicRequest":  {"topic_name": 1},
		"CreateTopicResponse": {"topic_id": 1},
		"DeleteTopicRequest":  {"topic_id": 1},
		"SubscribeRequest":    {"topic_id": 1, "queue_id": 2},
		"SubscribeResponse":   {"subscription_id": 1},
		"UnsubscribeRequest":  {"topic_id": 1, "subscription_id": 2},
		"PublishMessage":      {"body": 1},
		"PublishRequest":      {"topic_id": 1, "messages": 2},
		"PublishResponse":     {"topic_id": 1, "queue_ids": 2, "message_ids": 3, "delivered_count": 4},
	}
	for messageName, wantFields := range fields {
		message := File_v1_schema_proto.Messages().ByName(messageName)
		if message == nil {
			t.Errorf("stable message %s is missing", messageName)
			continue
		}
		for fieldName, wantNumber := range wantFields {
			field := message.Fields().ByName(fieldName)
			if field == nil || field.Number() != wantNumber {
				t.Errorf("%s.%s number = %v, want %d", messageName, fieldName, field, wantNumber)
			}
		}
	}
}

func leadingProtoComment(source, declaration string) (string, bool) {
	offset := strings.Index(source, declaration)
	if offset < 0 {
		return "", false
	}

	lines := strings.Split(source[:offset], "\n")
	comments := make([]string, 0)
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" && len(comments) == 0 {
			continue
		}
		if !strings.HasPrefix(line, "//") {
			break
		}
		comments = append([]string{strings.TrimSpace(strings.TrimPrefix(line, "//"))}, comments...)
	}

	return strings.Join(comments, " "), true
}

func TestStablePubSubDocumentation(t *testing.T) {
	t.Parallel()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve schema contract test path")
	}
	protoPath := filepath.Clean(filepath.Join(filepath.Dir(filename), "../../../../schema/v1/schema.proto"))
	sourceBytes, err := os.ReadFile(protoPath)
	if err != nil {
		t.Fatalf("read %s: %v", protoPath, err)
	}
	source := string(sourceBytes)

	cases := []struct {
		name        string
		declaration string
		phrases     []string
	}{
		{"topic", "message Topic {", []string{"XID", "unique", "stores no message bodies"}},
		{"subscription", "message Subscription {", []string{"XID", "(topic_id, queue_id)", "unique"}},
		{"publish", "rpc Publish(", []string{"zero subscriptions", "attempts every selected destination", "non-atomic across queues", "retry may duplicate"}},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			comments, found := leadingProtoComment(source, test.declaration)
			if !found {
				t.Fatalf("declaration %q is missing", test.declaration)
			}
			for _, phrase := range test.phrases {
				if !strings.Contains(comments, phrase) {
					t.Errorf("comments %q do not contain %q", comments, phrase)
				}
			}
		})
	}
}
