package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/plainq/internal/server/service/agent/conformance"
	agentstore "github.com/marsolab/plainq/internal/server/service/agent/litestore"
	queuestore "github.com/marsolab/plainq/internal/server/service/queue/litestore"
	"github.com/marsolab/plainq/internal/shared/pqlite"
	"github.com/marsolab/servekit/logkit"
)

const (
	tursoURLEnv       = "PLAINQ_TEST_TURSO_URL"
	tursoTokenEnv     = "PLAINQ_TEST_TURSO_AUTH_TOKEN"
	tursoChildCaseEnv = "PLAINQ_TEST_TURSO_CHILD_CASE"
	sqldImage         = "ghcr.io/tursodatabase/libsql-server:latest"
)

// TestTursoBackendIntegration drives a real libSQL server through the same
// code path the server uses: open the backend, migrate the schema, then run
// queue operations against the litestore. It covers what unit tests against
// local SQLite cannot — the hrana wire protocol, batched multi-statement
// migrations, and the TIMESTAMP-to-time.Time round-trip.
func TestTursoBackendIntegration(t *testing.T) {
	runWithOwnedSqld(t, runTursoBackendIntegration)
}

func runTursoBackendIntegration(t *testing.T) {
	dbURL := os.Getenv(tursoURLEnv)
	if dbURL == "" {
		t.Fatalf("child %s is not set", tursoURLEnv)
	}

	cfg := config.Config{
		StorageDriver:         storageDriverTurso,
		StorageTursoURL:       dbURL,
		StorageTursoAuthToken: os.Getenv(tursoTokenEnv),
	}

	logger := logkit.NewNop()

	backend, err := initStorageBackend(&cfg, logger)
	if err != nil {
		t.Fatalf("init turso backend: %v", err)
	}

	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close backend: %v", err)
		}
	})

	if backend.driver != storageDriverTurso {
		t.Fatalf("driver: got %q, want %q", backend.driver, storageDriverTurso)
	}

	if got, want := schemaVersion(t, backend.turso), lastMutationVersion(t); got != want {
		t.Errorf("schema version: got %d, want %d", got, want)
	}

	ctx := context.Background()

	store, err := queuestore.New(backend.lite(), queuestore.WithLogger(slog.New(slog.DiscardHandler)))
	if err != nil {
		t.Fatalf("create queue storage: %v", err)
	}

	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close queue storage: %v", err)
		}
	})

	created, err := store.CreateQueue(ctx, &v1.CreateQueueRequest{QueueName: "integration"})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	queueID := created.GetQueueId()

	t.Cleanup(func() {
		if _, err := store.DeleteQueue(ctx, &v1.DeleteQueueRequest{QueueId: queueID}); err != nil {
			t.Errorf("delete queue: %v", err)
		}
	})

	// DescribeQueue reads created_at out of a TIMESTAMP column, which is the
	// conversion that only works when the driver reports declared types.
	if _, err := store.DescribeQueue(ctx, &v1.DescribeQueueRequest{QueueId: queueID}); err != nil {
		t.Fatalf("describe queue: %v", err)
	}

	body := []byte("hello from turso")

	if _, err := store.Send(ctx, &v1.SendRequest{
		QueueId:  queueID,
		Messages: []*v1.SendMessage{{Body: body}},
	}); err != nil {
		t.Fatalf("send message: %v", err)
	}

	received, err := store.Receive(ctx, &v1.ReceiveRequest{QueueId: queueID, BatchSize: 1})
	if err != nil {
		t.Fatalf("receive message: %v", err)
	}

	messages := received.GetMessages()
	if len(messages) != 1 {
		t.Fatalf("received messages: got %d, want 1", len(messages))
	}

	if !bytes.Equal(messages[0].GetBody(), body) {
		t.Errorf("message body: got %q, want %q", messages[0].GetBody(), body)
	}

	if _, err := store.Delete(ctx, &v1.DeleteRequest{
		QueueId:    queueID,
		MessageIds: []string{messages[0].GetId()},
	}); err != nil {
		t.Fatalf("delete message: %v", err)
	}

	// Opening a second storage over the same database exercises what only
	// happens on restart: filling the cache from queue_properties, and the
	// correlated pragma_table_info the queue-table repair runs. Both are
	// worth proving against the real wire protocol rather than local SQLite.
	reopened, err := queuestore.New(backend.lite(), queuestore.WithLogger(slog.New(slog.DiscardHandler)))
	if err != nil {
		t.Fatalf("reopen queue storage: %v", err)
	}

	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened queue storage: %v", err)
		}
	})

	listed, err := reopened.ListQueues(ctx, &v1.ListQueuesRequest{})
	if err != nil {
		t.Fatalf("list queues after reopen: %v", err)
	}

	if len(listed.GetQueues()) == 0 {
		t.Error("queues after reopen: got none, want the queue created above")
	}
}

func TestTursoForeignKeys(t *testing.T) {
	runWithOwnedSqld(t, func(t *testing.T) {
		backend := openTursoTestBackend(t)
		ctx := context.Background()

		connections := make([]*sql.Conn, 0, 2)
		for range 2 {
			conn, err := backend.turso.Conn(ctx)
			if err != nil {
				t.Fatalf("acquire turso connection: %v", err)
			}
			connections = append(connections, conn)
		}
		defer func() {
			for _, conn := range connections {
				if err := conn.Close(); err != nil {
					t.Errorf("close turso connection: %v", err)
				}
			}
		}()

		for index, conn := range connections {
			if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
				t.Fatalf("connection %d enable foreign keys: %v", index+1, err)
			}
			var enabled int
			if err := conn.QueryRowContext(ctx, `PRAGMA foreign_keys`).Scan(&enabled); err != nil {
				t.Fatalf("connection %d read foreign_keys: %v", index+1, err)
			}
			if enabled != 1 {
				t.Fatalf("connection %d foreign_keys = %d, want 1", index+1, enabled)
			}

			tx, err := conn.BeginTx(ctx, nil)
			if err != nil {
				t.Fatalf("connection %d begin orphan probe: %v", index+1, err)
			}
			_, insertErr := tx.ExecContext(ctx, `
				INSERT INTO agents (
					agent_id, tenant_id, agent_name, status, auth_version,
					created_by_kind, created_by_id, created_at_ns, updated_at_ns
				) VALUES (?, ?, ?, 1, 1, 'system', 'integration-probe', 0, 0)`,
				fmt.Sprintf("turso-fk-probe-%d", index+1),
				fmt.Sprintf("turso-missing-tenant-%d", index+1),
				fmt.Sprintf("turso-fk-probe-%d", index+1),
			)
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				t.Fatalf("connection %d rollback orphan probe: %v", index+1, err)
			}
			if insertErr == nil || !strings.Contains(strings.ToUpper(insertErr.Error()), "FOREIGN KEY") {
				t.Fatalf("connection %d orphan insert error = %v, want foreign-key failure", index+1, insertErr)
			}
		}
	})
}

func TestTursoAgentConformance(t *testing.T) {
	runWithOwnedSqld(t, func(t *testing.T) {
		backend := openTursoTestBackend(t)
		conformance.Registry(t, func(t *testing.T) conformance.RegistryFixture {
			t.Helper()
			ctx := context.Background()
			if err := pqlite.WithWriteTx(ctx, backend.lite(), pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
				for _, statement := range []string{
					`DELETE FROM security_principals`,
					`DELETE FROM agents`,
					`DELETE FROM organizations WHERE org_id LIKE 'tenant-%'`,
				} {
					if _, err := tx.ExecContext(ctx, statement); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				t.Fatalf("reset turso registry fixture: %v", err)
			}

			store, err := agentstore.NewStorage(backend.lite())
			if err != nil {
				t.Fatalf("create turso agent store: %v", err)
			}
			return &tursoRegistryFixture{Storage: store, db: backend.lite()}
		})
	})
}

type tursoRegistryFixture struct {
	*agentstore.Storage
	db pqlite.DB
}

func (f *tursoRegistryFixture) SeedOrganization(ctx context.Context, tenantID string) error {
	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO organizations (org_id, org_code, org_name)
			VALUES (?, ?, ?)`, tenantID, tenantID, tenantID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_quotas (
				tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
				max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
				publish_per_second, updated_at_ns
			) VALUES (?, 10000, 2, 10000, 1000, 1000, 1048576, 10737418240, 1000, 1000, 0)`,
			tenantID,
		); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_resource_usage (
				tenant_id, agent_count, queue_count, topic_count, subscription_count,
				stored_messaging_bytes, updated_at_ns
			) VALUES (?, 0, 0, 0, 0, 0, 0)`, tenantID)

		return err
	})
}

func (f *tursoRegistryFixture) SeedAgentPrincipal(ctx context.Context, tenantID, agentID string) error {
	return pqlite.WithWriteTx(ctx, f.db, pqlite.DefaultWriteRetry(), func(tx pqlite.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO security_principals (
				tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
			) VALUES (?, 'agent', ?, 'active', '["agent"]', 1, 0)`, tenantID, agentID)
		return err
	})
}

func (f *tursoRegistryFixture) AgentPrincipal(
	ctx context.Context, tenantID, agentID string,
) (string, uint64, error) {
	var status string
	var authVersion int64
	err := f.db.QueryRowContext(ctx, `
		SELECT status, auth_version
		FROM security_principals
		WHERE tenant_id = ? AND principal_kind = 'agent' AND principal_id = ?`, tenantID, agentID,
	).Scan(&status, &authVersion)
	return status, uint64(authVersion), err
}

func openTursoTestBackend(t *testing.T) *storageBackend {
	t.Helper()

	cfg := config.Config{
		StorageDriver:         storageDriverTurso,
		StorageTursoURL:       os.Getenv(tursoURLEnv),
		StorageTursoAuthToken: os.Getenv(tursoTokenEnv),
	}
	backend, err := initStorageBackend(&cfg, logkit.NewNop())
	if err != nil {
		t.Fatalf("init turso backend: %v", err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close turso backend: %v", err)
		}
	})

	return backend
}

func runWithOwnedSqld(t *testing.T, child func(*testing.T)) {
	t.Helper()

	if os.Getenv(tursoChildCaseEnv) == t.Name() {
		child(t)
		return
	}

	dbURL := startSqld(t)
	command := exec.Command(os.Args[0], "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.v")
	command.Env = childEnvironment(t.Name(), dbURL)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("turso child test failed: %v\n%s", err, output)
	}
	t.Logf("turso child test passed:\n%s", output)
}

func childEnvironment(testName, dbURL string) []string {
	overrides := map[string]string{
		tursoChildCaseEnv: testName,
		tursoURLEnv:       dbURL,
		tursoTokenEnv:     "",
	}

	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, item := range os.Environ() {
		key, _, _ := strings.Cut(item, "=")
		if _, replaced := overrides[key]; !replaced {
			environment = append(environment, item)
		}
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}

	return environment
}

func startSqld(t *testing.T) string {
	t.Helper()

	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is not installed; skipping owned sqld integration")
	}
	if output, err := exec.Command(docker, "info").CombinedOutput(); err != nil {
		t.Skipf("docker daemon is unavailable: %v: %s", err, output)
	}

	name := fmt.Sprintf("plainq-sqld-%d-%d", os.Getpid(), time.Now().UnixNano())
	cidFile := filepath.Join(t.TempDir(), "sqld.cid")
	command := exec.Command(docker, sqldContainerRunArgs(name, cidFile)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("start sqld container: %v: %s", err, output)
	}

	// Docker writes image-pull progress to the same combined stream that used
	// to be parsed as the container ID. A cidfile remains unambiguous on a
	// cold runner, even when the image has to be downloaded first.
	cidOutput, err := os.ReadFile(cidFile)
	if err != nil {
		_, _ = exec.Command(docker, "rm", "-f", name).CombinedOutput()
		t.Fatalf("read sqld container id: %v; docker output: %s", err, output)
	}
	containerID := strings.TrimSpace(string(cidOutput))
	if containerID == "" {
		_, _ = exec.Command(docker, "rm", "-f", name).CombinedOutput()
		t.Fatalf("read sqld container id: cidfile is empty; docker output: %s", output)
	}
	t.Cleanup(func() {
		if output, err := exec.Command(docker, "rm", "-f", containerID).CombinedOutput(); err != nil &&
			!strings.Contains(string(output), "No such container") {
			t.Errorf("remove sqld container: %v: %s", err, output)
		}
	})

	port, err := waitForDockerPort(300, func() ([]byte, error) {
		inspect := exec.Command(
			docker, "inspect", "--format",
			`{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}`, containerID,
		)
		return inspect.CombinedOutput()
	}, func() {
		time.Sleep(100 * time.Millisecond)
	})
	if err != nil {
		t.Fatalf("inspect sqld port: %v", err)
	}

	dbURL := "http://127.0.0.1:" + port
	waitForSqld(t, docker, containerID, dbURL)
	return dbURL
}

func sqldContainerRunArgs(name, cidFile string) []string {
	return []string{
		"run", "--rm", "-d", "--name", name,
		"--cidfile", cidFile,
		"-p", "127.0.0.1::8080", "-e", "SQLD_NODE=primary", sqldImage,
	}
}

func waitForDockerPort(
	maxAttempts int,
	inspect func() ([]byte, error),
	wait func(),
) (string, error) {
	if maxAttempts < 1 {
		return "", errors.New("inspect mapped sqld port: max attempts must be positive")
	}

	var (
		lastOutput []byte
		lastErr    error
	)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		output, err := inspect()
		lastOutput = output
		lastErr = err

		port := strings.TrimSpace(string(output))
		if err == nil {
			portNumber, parseErr := strconv.Atoi(port)
			switch {
			case parseErr != nil:
				lastErr = fmt.Errorf("invalid mapped port %q: %w", port, parseErr)
			case portNumber < 1 || portNumber > 65535:
				lastErr = fmt.Errorf("mapped port %d is outside the valid range", portNumber)
			default:
				return port, nil
			}
		}

		if attempt < maxAttempts {
			wait()
		}
	}

	return "", fmt.Errorf(
		"inspect mapped sqld port after %d attempts: %w; last output: %s",
		maxAttempts,
		lastErr,
		strings.TrimSpace(string(lastOutput)),
	)
}

func waitForSqld(t *testing.T, docker, containerID, dbURL string) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	client := &http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		response, err := client.Get(dbURL + "/health")
		if err == nil {
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	logs, _ := exec.Command(docker, "logs", containerID).CombinedOutput()
	t.Fatalf("sqld health probe did not become ready at %s: %s", dbURL, logs)
}
