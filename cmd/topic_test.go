package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testTopicID        = "D8VEKIMGOO6F7O6LNLN0"
	testQueueID        = "D1MHTM0EFR7CBTQ8SL3G"
	testSubscriptionID = "D9JLNDRE72TK20F60HQ0"
)

func TestTopicCommandDiscoveryAndSchemaOrder(t *testing.T) {
	root := testRoot(t)
	topic := root.lookup("topic")
	if topic == nil {
		t.Fatal("topic command not found")
	}

	wantNames := []string{"list", "create", "delete", "subscribe", "unsubscribe", "publish"}
	gotNames := make([]string, 0, len(topic.Subcommands))
	for _, leaf := range topic.Subcommands {
		gotNames = append(gotNames, leaf.Name)
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("topic leaves = %v, want %v", gotNames, wantNames)
	}

	wantEffects := map[string]commandEffect{
		"list":        effectReadOnly,
		"create":      effectMutating,
		"delete":      effectDestructive,
		"subscribe":   effectMutating,
		"unsubscribe": effectDestructive,
		"publish":     effectMutating,
	}
	for _, leaf := range topic.Subcommands {
		if leaf.Effect != wantEffects[leaf.Name] {
			t.Errorf("topic %s effect = %q, want %q", leaf.Name, leaf.Effect, wantEffects[leaf.Name])
		}
		if leaf.command().Flags().Lookup(flagGRPCAddr) == nil {
			t.Errorf("topic %s is missing -%s", leaf.Name, flagGRPCAddr)
		}
		if leaf.command().Flags().Lookup(flagJSON) == nil {
			t.Errorf("topic %s is missing -%s", leaf.Name, flagJSON)
		}
	}

	out, err := buildSchema(root, schemaTargetCLI)
	if err != nil {
		t.Fatalf("build CLI schema: %v", err)
	}

	var schemaNames []string
	for _, command := range out.CLI.Commands {
		if command.Name != "topic" {
			continue
		}
		for _, leaf := range command.Subcommands {
			schemaNames = append(schemaNames, leaf.Name)
		}
	}
	if !slices.Equal(schemaNames, wantNames) {
		t.Fatalf("schema topic leaves = %v, want %v", schemaNames, wantNames)
	}
}

func TestTopicUsageDocumentsEveryLeaf(t *testing.T) {
	root := testRoot(t)
	topic := root.lookup("topic")
	if topic == nil {
		t.Fatal("topic command not found")
	}

	wantUsage := map[string]string{
		"list":        "plainq topic list [flags]",
		"create":      "plainq topic create [flags] <topic-name>",
		"delete":      "plainq topic delete [flags] <topic-id>",
		"subscribe":   "plainq topic subscribe [flags] <topic-id> <queue-id>",
		"unsubscribe": "plainq topic unsubscribe [flags] <topic-id> <subscription-id>",
		"publish":     "plainq topic publish [flags] <topic-id>",
	}

	for _, leaf := range topic.Subcommands {
		t.Run(leaf.Name, func(t *testing.T) {
			var output strings.Builder
			leaf.printUsage(&output)

			help := output.String()
			for _, want := range []string{wantUsage[leaf.Name], "Examples:", "Effect:", "Exit codes:"} {
				if !strings.Contains(help, want) {
					t.Errorf("help is missing %q\n---\n%s", want, help)
				}
			}
		})
	}
}

func TestTopicHelpAliasesInSubprocess(t *testing.T) {
	for _, alias := range []string{"-h", "-help", "--help"} {
		t.Run(alias, func(t *testing.T) {
			command := exec.Command(os.Args[0], "-test.run=TestTopicHelpHelperProcess")
			command.Env = append(
				os.Environ(),
				"PLAINQ_TOPIC_HELP_ALIAS="+alias,
				"PLAINQ_CONTEXT_FILE="+filepath.Join(t.TempDir(), "absent.json"),
				"PLAINQ_ADDR=",
			)

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("help %s: %v\n%s", alias, err, output)
			}
			if !strings.Contains(string(output), "plainq topic publish [flags] <topic-id>") {
				t.Errorf("help %s output is missing publish usage:\n%s", alias, output)
			}
		})
	}
}

func TestTopicHelpHelperProcess(t *testing.T) {
	alias := os.Getenv("PLAINQ_TOPIC_HELP_ALIAS")
	if alias == "" {
		return
	}

	rootName = "plainq"
	root := rootCommand()
	command := root.command()
	args := []string{"topic", "publish", alias}
	os.Args = append([]string{"plainq"}, normalizeArgs(root, args)...)

	if err := command.Exec(); err != nil {
		t.Fatalf("topic help: %v", err)
	}

	t.Fatal("Scotty help returned instead of exiting")
}

func TestTopicExactArityFailsBeforeOpen(t *testing.T) {
	tests := map[string][]string{
		"list extra":              {"list", "extra"},
		"create missing":          {"create"},
		"create extra":            {"create", "orders", "extra"},
		"delete missing":          {"delete"},
		"delete extra":            {"delete", testTopicID, "extra"},
		"subscribe missing queue": {"subscribe", testTopicID},
		"subscribe extra":         {"subscribe", testTopicID, testQueueID, "extra"},
		"unsubscribe missing id":  {"unsubscribe", testTopicID},
		"unsubscribe extra":       {"unsubscribe", testTopicID, testSubscriptionID, "extra"},
		"publish missing topic":   {"publish", "-message=hello"},
		"publish extra":           {"publish", testTopicID, "extra", "-message=hello"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			open := newTopicOpenRecorder()
			err := executeTopic(t, args, topicCommandDeps{
				open:   open.Open,
				stdin:  strings.NewReader(""),
				stdout: io.Discard,
			})

			assertExitCode(t, err, exitUsage)
			if open.calls != 0 {
				t.Errorf("open calls = %d, want 0", open.calls)
			}
		})
	}
}

func TestTopicValidationAndInputFailBeforeOpen(t *testing.T) {
	overLimit := strings.NewReader(strings.Repeat("x", maxMessageLineBytes+1))

	tests := map[string]struct {
		args  []string
		stdin io.Reader
	}{
		"blank topic name": {
			args: []string{"create", "   "},
		},
		"invalid topic id": {
			args: []string{"delete", "not-an-id"},
		},
		"invalid subscribe topic": {
			args: []string{"subscribe", "not-an-id", testQueueID},
		},
		"invalid subscribe queue": {
			args: []string{"subscribe", testTopicID, "orders"},
		},
		"invalid subscription id": {
			args: []string{"unsubscribe", testTopicID, "not-an-id"},
		},
		"publish without bodies": {
			args: []string{"publish", testTopicID},
		},
		"publish empty file": {
			args:  []string{"publish", testTopicID, "-file=-"},
			stdin: strings.NewReader("\n\n"),
		},
		"publish oversized line": {
			args:  []string{"publish", testTopicID, "-file=-"},
			stdin: overLimit,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			open := newTopicOpenRecorder()
			stdin := tc.stdin
			if stdin == nil {
				stdin = strings.NewReader("")
			}

			err := executeTopic(t, tc.args, topicCommandDeps{
				open:   open.Open,
				stdin:  stdin,
				stdout: io.Discard,
			})

			assertExitCode(t, err, exitUsage)
			if open.calls != 0 {
				t.Errorf("open calls = %d, want 0", open.calls)
			}
		})
	}
}

func TestTopicTextCommandsPreserveRequestsAndClose(t *testing.T) {
	tests := map[string]struct {
		args        []string
		configure   func(*topicClientFake)
		wantOutput  string
		wantRequest any
	}{
		"list": {
			args: []string{"list"},
			configure: func(client *topicClientFake) {
				client.listResponse = &v1.ListTopicsResponse{Topics: []*v1.Topic{
					{TopicId: testTopicID, TopicName: "orders"},
					{TopicId: testQueueID, TopicName: "events"},
				}}
			},
			wantOutput:  testTopicID + " | orders\n" + testQueueID + " | events\n",
			wantRequest: &v1.ListTopicsRequest{},
		},
		"create preserves whitespace": {
			args: []string{"create", " Orders "},
			configure: func(client *topicClientFake) {
				client.createResponse = &v1.CreateTopicResponse{TopicId: testTopicID}
			},
			wantOutput:  testTopicID + "\n",
			wantRequest: &v1.CreateTopicRequest{TopicName: " Orders "},
		},
		"delete preserves uppercase": {
			args:        []string{"delete", testTopicID},
			wantOutput:  "deleted\t" + testTopicID + "\n",
			wantRequest: &v1.DeleteTopicRequest{TopicId: testTopicID},
		},
		"subscribe preserves uppercase": {
			args: []string{"subscribe", testTopicID, testQueueID},
			configure: func(client *topicClientFake) {
				client.subscribeResponse = &v1.SubscribeResponse{SubscriptionId: testSubscriptionID}
			},
			wantOutput: testSubscriptionID + "\n",
			wantRequest: &v1.SubscribeRequest{
				TopicId: testTopicID,
				QueueId: testQueueID,
			},
		},
		"unsubscribe preserves uppercase": {
			args:       []string{"unsubscribe", testTopicID, testSubscriptionID},
			wantOutput: "unsubscribed\t" + testSubscriptionID + "\n",
			wantRequest: &v1.UnsubscribeRequest{
				TopicId:        testTopicID,
				SubscriptionId: testSubscriptionID,
			},
		},
		"publish preserves uppercase and empty message": {
			args: []string{"publish", testTopicID, "-message=", "-message=hello"},
			configure: func(client *topicClientFake) {
				client.publishResponse = &v1.PublishResponse{TopicId: testTopicID, DeliveredCount: 2}
			},
			wantOutput: "delivered\t2\n",
			wantRequest: &v1.PublishRequest{
				TopicId: testTopicID,
				Messages: []*v1.PublishMessage{
					{Body: []byte{}},
					{Body: []byte("hello")},
				},
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTopicClientFake()
			if tc.configure != nil {
				tc.configure(client)
			}
			closer := &topicCloserFake{}
			open := &topicOpenRecorder{client: client, closer: closer}
			var stdout bytes.Buffer

			err := executeTopic(t, tc.args, topicCommandDeps{
				open:   open.Open,
				stdin:  strings.NewReader(""),
				stdout: &stdout,
			})
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if stdout.String() != tc.wantOutput {
				t.Errorf("stdout = %q, want %q", stdout.String(), tc.wantOutput)
			}
			if open.calls != 1 {
				t.Errorf("open calls = %d, want 1", open.calls)
			}
			if closer.calls != 1 {
				t.Errorf("close calls = %d, want 1", closer.calls)
			}
			if len(client.calls) != 1 {
				t.Fatalf("RPC calls = %d, want 1", len(client.calls))
			}
			if !reflect.DeepEqual(client.calls[0].request, tc.wantRequest) {
				t.Errorf("request = %#v, want %#v", client.calls[0].request, tc.wantRequest)
			}
		})
	}
}

func TestTopicJSONCommandsRenderRawResponses(t *testing.T) {
	tests := map[string]struct {
		args      []string
		configure func(*topicClientFake)
		wantJSON  string
	}{
		"list": {
			args: []string{"list", "-json"},
			configure: func(client *topicClientFake) {
				client.listResponse = &v1.ListTopicsResponse{Topics: []*v1.Topic{{
					TopicId: testTopicID, TopicName: "orders",
				}}}
			},
			wantJSON: `{"topics":[{"topicId":"` + testTopicID + `","topicName":"orders"}]}`,
		},
		"create": {
			args: []string{"create", "orders", "-json"},
			configure: func(client *topicClientFake) {
				client.createResponse = &v1.CreateTopicResponse{TopicId: testTopicID}
			},
			wantJSON: `{"topicId":"` + testTopicID + `"}`,
		},
		"delete": {
			args:     []string{"delete", testTopicID, "-json"},
			wantJSON: `{}`,
		},
		"subscribe": {
			args: []string{"subscribe", testTopicID, testQueueID, "-json"},
			configure: func(client *topicClientFake) {
				client.subscribeResponse = &v1.SubscribeResponse{SubscriptionId: testSubscriptionID}
			},
			wantJSON: `{"subscriptionId":"` + testSubscriptionID + `"}`,
		},
		"unsubscribe": {
			args:     []string{"unsubscribe", testTopicID, testSubscriptionID, "-json"},
			wantJSON: `{}`,
		},
		"publish": {
			args: []string{"publish", testTopicID, "-message=hello", "-json"},
			configure: func(client *topicClientFake) {
				client.publishResponse = &v1.PublishResponse{
					TopicId:        testTopicID,
					QueueIds:       []string{testQueueID},
					MessageIds:     []string{testSubscriptionID},
					DeliveredCount: 1,
				}
			},
			wantJSON: `{"topicId":"` + testTopicID + `","queueIds":["` + testQueueID + `"],` +
				`"messageIds":["` + testSubscriptionID + `"],"deliveredCount":"1"}`,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTopicClientFake()
			if tc.configure != nil {
				tc.configure(client)
			}
			closer := &topicCloserFake{}
			open := &topicOpenRecorder{client: client, closer: closer}
			var stdout bytes.Buffer

			err := executeTopic(t, tc.args, topicCommandDeps{
				open:   open.Open,
				stdin:  strings.NewReader(""),
				stdout: &stdout,
			})
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			assertJSONEqual(t, stdout.Bytes(), []byte(tc.wantJSON))
		})
	}
}

func TestTopicPublishAcceptsFlagOrderingAndMixedInput(t *testing.T) {
	tests := map[string][]string{
		"flag before positional with two dashes": {"publish", "--message", "flag", testTopicID, "--file", "-"},
		"flags after positional with one dash":   {"publish", testTopicID, "-message=flag", "-file=-"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			client := newTopicClientFake()
			open := &topicOpenRecorder{client: client, closer: &topicCloserFake{}}

			err := executeTopic(t, args, topicCommandDeps{
				open:   open.Open,
				stdin:  strings.NewReader("file-one\n\nfile-two\n"),
				stdout: io.Discard,
			})
			if err != nil {
				t.Fatalf("execute: %v", err)
			}

			request := client.calls[0].request.(*v1.PublishRequest)
			got := make([][]byte, 0, len(request.GetMessages()))
			for _, message := range request.GetMessages() {
				got = append(got, message.GetBody())
			}
			want := [][]byte{[]byte("flag"), []byte("file-one"), []byte("file-two")}
			if !equalBodies(got, want) {
				t.Errorf("publish bodies = %q, want %q", got, want)
			}
		})
	}
}

func TestTopicClientLifecycleAndFailures(t *testing.T) {
	openErr := errors.New("dial failed")
	rpcErr := status.Error(codes.NotFound, "topic does not exist")
	renderErr := errors.New("write failed")
	closeErr := errors.New("close failed")

	tests := map[string]struct {
		open       *topicOpenRecorder
		stdout     io.Writer
		want       []error
		wantExit   int
		wantClose  int
		wantAdvice bool
	}{
		"open failure": {
			open:     &topicOpenRecorder{err: openErr},
			stdout:   io.Discard,
			want:     []error{openErr},
			wantExit: exitFailure,
		},
		"RPC failure": {
			open: &topicOpenRecorder{
				client: &topicClientFake{listResponse: &v1.ListTopicsResponse{}, err: rpcErr},
				closer: &topicCloserFake{},
			},
			stdout:     io.Discard,
			want:       []error{rpcErr},
			wantExit:   exitFailure,
			wantClose:  1,
			wantAdvice: true,
		},
		"render failure": {
			open: &topicOpenRecorder{
				client: &topicClientFake{listResponse: &v1.ListTopicsResponse{Topics: []*v1.Topic{{
					TopicId: testTopicID,
				}}}},
				closer: &topicCloserFake{},
			},
			stdout:    failWriter{err: renderErr},
			want:      []error{renderErr},
			wantExit:  exitFailure,
			wantClose: 1,
		},
		"close-only failure": {
			open: &topicOpenRecorder{
				client: newTopicClientFake(),
				closer: &topicCloserFake{err: closeErr},
			},
			stdout:    io.Discard,
			want:      []error{closeErr},
			wantExit:  exitFailure,
			wantClose: 1,
		},
		"operation and close failure": {
			open: &topicOpenRecorder{
				client: &topicClientFake{listResponse: &v1.ListTopicsResponse{}, err: rpcErr},
				closer: &topicCloserFake{err: closeErr},
			},
			stdout:     io.Discard,
			want:       []error{rpcErr, closeErr},
			wantExit:   exitFailure,
			wantClose:  1,
			wantAdvice: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := executeTopic(t, []string{"list"}, topicCommandDeps{
				open:   tc.open.Open,
				stdin:  strings.NewReader(""),
				stdout: tc.stdout,
			})

			assertExitCode(t, err, tc.wantExit)
			for _, want := range tc.want {
				if !errors.Is(err, want) {
					t.Errorf("error %v does not contain %v", err, want)
				}
			}
			if tc.open.calls != 1 {
				t.Errorf("open calls = %d, want 1", tc.open.calls)
			}
			if tc.open.closer != nil {
				closer := tc.open.closer.(*topicCloserFake)
				if closer.calls != tc.wantClose {
					t.Errorf("close calls = %d, want %d", closer.calls, tc.wantClose)
				}
			}
			if tc.wantAdvice && !strings.Contains(err.Error(), "plainq topic list") {
				t.Errorf("error = %q, want topic list advice", err)
			}
		})
	}
}

func executeTopic(t *testing.T, args []string, deps topicCommandDeps) error {
	t.Helper()

	t.Setenv(envContextFile, filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv(envGRPCAddr, "")

	oldArgs := os.Args
	oldFlags := flag.CommandLine
	oldRootName := rootName
	t.Cleanup(func() {
		os.Args = oldArgs
		flag.CommandLine = oldFlags
		rootName = oldRootName
	})

	rootName = "plainq"
	root := &commandSpec{
		Name:        "plainq",
		Short:       "test root",
		Long:        "test root",
		Subcommands: []*commandSpec{newTopicCommand(deps)},
	}
	command := root.command()
	fullArgs := append([]string{"topic"}, args...)
	os.Args = append([]string{"plainq"}, normalizeArgs(root, fullArgs)...)

	return command.Exec()
}

func assertExitCode(t *testing.T, err error, want int) {
	t.Helper()

	if err == nil {
		t.Fatalf("error = nil, want exit %d", want)
	}
	if got := reportError(io.Discard, err); got != want {
		t.Fatalf("exit code = %d, want %d (%v)", got, want, err)
	}
}

func assertJSONEqual(t *testing.T, got, want []byte) {
	t.Helper()

	var gotValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode output JSON: %v\n%s", err, got)
	}

	var wantValue any
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatalf("decode wanted JSON: %v\n%s", err, want)
	}

	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

type topicRPC struct {
	operation string
	request   any
	options   []grpc.CallOption
}

type topicClientFake struct {
	listResponse        *v1.ListTopicsResponse
	createResponse      *v1.CreateTopicResponse
	deleteResponse      *v1.DeleteTopicResponse
	subscribeResponse   *v1.SubscribeResponse
	unsubscribeResponse *v1.UnsubscribeResponse
	publishResponse     *v1.PublishResponse
	err                 error
	calls               []topicRPC
}

func newTopicClientFake() *topicClientFake {
	return &topicClientFake{
		listResponse:        &v1.ListTopicsResponse{},
		createResponse:      &v1.CreateTopicResponse{},
		deleteResponse:      &v1.DeleteTopicResponse{},
		subscribeResponse:   &v1.SubscribeResponse{},
		unsubscribeResponse: &v1.UnsubscribeResponse{},
		publishResponse:     &v1.PublishResponse{},
	}
}

func (f *topicClientFake) record(operation string, request any, options []grpc.CallOption) {
	f.calls = append(f.calls, topicRPC{operation: operation, request: request, options: options})
}

func (f *topicClientFake) ListTopics(
	_ context.Context,
	request *v1.ListTopicsRequest,
	options ...grpc.CallOption,
) (*v1.ListTopicsResponse, error) {
	f.record("list", request, options)

	return f.listResponse, f.err
}

func (f *topicClientFake) CreateTopic(
	_ context.Context,
	request *v1.CreateTopicRequest,
	options ...grpc.CallOption,
) (*v1.CreateTopicResponse, error) {
	f.record("create", request, options)

	return f.createResponse, f.err
}

func (f *topicClientFake) DeleteTopic(
	_ context.Context,
	request *v1.DeleteTopicRequest,
	options ...grpc.CallOption,
) (*v1.DeleteTopicResponse, error) {
	f.record("delete", request, options)

	return f.deleteResponse, f.err
}

func (f *topicClientFake) Subscribe(
	_ context.Context,
	request *v1.SubscribeRequest,
	options ...grpc.CallOption,
) (*v1.SubscribeResponse, error) {
	f.record("subscribe", request, options)

	return f.subscribeResponse, f.err
}

func (f *topicClientFake) Unsubscribe(
	_ context.Context,
	request *v1.UnsubscribeRequest,
	options ...grpc.CallOption,
) (*v1.UnsubscribeResponse, error) {
	f.record("unsubscribe", request, options)

	return f.unsubscribeResponse, f.err
}

func (f *topicClientFake) Publish(
	_ context.Context,
	request *v1.PublishRequest,
	options ...grpc.CallOption,
) (*v1.PublishResponse, error) {
	f.record("publish", request, options)

	return f.publishResponse, f.err
}

type topicCloserFake struct {
	calls int
	err   error
}

func (c *topicCloserFake) Close() error {
	c.calls++

	return c.err
}

type topicOpenRecorder struct {
	client topicClient
	closer io.Closer
	err    error
	calls  int
	addrs  []string
}

func newTopicOpenRecorder() *topicOpenRecorder {
	return &topicOpenRecorder{client: newTopicClientFake(), closer: &topicCloserFake{}}
}

func (o *topicOpenRecorder) Open(_ context.Context, addr string) (topicClient, io.Closer, error) {
	o.calls++
	o.addrs = append(o.addrs, addr)

	return o.client, o.closer, o.err
}

type failWriter struct{ err error }

func (w failWriter) Write(_ []byte) (int, error) { return 0, w.err }

func (r topicRPC) String() string { return fmt.Sprintf("%s %#v", r.operation, r.request) }
