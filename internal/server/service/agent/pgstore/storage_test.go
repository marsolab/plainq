package pgstore

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
	agentv1 "github.com/marsolab/plainq/internal/server/schema/agent/v1"
	"github.com/marsolab/plainq/internal/server/service/agent/conformance"
)

type registryFixture struct {
	*Storage
	pool *pgxpool.Pool
}

func (f *registryFixture) SeedOrganization(ctx context.Context, tenantID string) error {
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		INSERT INTO organizations (org_id, org_code, org_name)
		VALUES ($1, $2, $3)`, tenantID, tenantID, tenantID); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_quotas (
			tenant_id, max_agents, max_credentials_per_agent, max_queues, max_topics,
			max_subscriptions, max_message_bytes, max_stored_bytes, send_per_second,
			publish_per_second, updated_at_ns
		) VALUES ($1, 10000, 2, 10000, 1000, 1000, 1048576, 10737418240, 1000, 1000, 0)`,
		tenantID,
	); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_resource_usage (
			tenant_id, agent_count, queue_count, topic_count, subscription_count,
			stored_messaging_bytes, updated_at_ns
		) VALUES ($1, 0, 0, 0, 0, 0, 0)`, tenantID); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (f *registryFixture) SeedAgentPrincipal(ctx context.Context, tenantID, agentID string) error {
	_, err := f.pool.Exec(ctx, `
		INSERT INTO security_principals (
			tenant_id, principal_kind, principal_id, status, roles_json, auth_version, updated_at_ns
		) VALUES ($1, 'agent', $2, 'active', '["agent"]'::jsonb, 1, 0)`, tenantID, agentID)
	return err
}

func (f *registryFixture) AgentPrincipal(ctx context.Context, tenantID, agentID string) (string, uint64, error) {
	var status string
	var authVersion int64
	err := f.pool.QueryRow(ctx, `
		SELECT status, auth_version
		FROM security_principals
		WHERE tenant_id = $1 AND principal_kind = 'agent' AND principal_id = $2`, tenantID, agentID,
	).Scan(&status, &authVersion)
	return status, uint64(authVersion), err
}

func (f *registryFixture) SetAgentPrincipalProjection(
	ctx context.Context,
	tenantID string,
	agentID string,
	status agentv1.AgentStatus,
	authVersion uint64,
) error {
	storedStatus := "active"
	if status == agentv1.AgentStatus_AGENT_STATUS_DISABLED {
		storedStatus = "disabled"
	}

	_, err := f.pool.Exec(ctx, `
		UPDATE security_principals
		SET status = $1, auth_version = $2
		WHERE tenant_id = $3 AND principal_kind = 'agent' AND principal_id = $4`,
		storedStatus, int64(authVersion), tenantID, agentID)

	return err
}

func newRegistryFixture(t *testing.T) conformance.RegistryFixture {
	t.Helper()

	dsn := os.Getenv("PLAINQ_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("PLAINQ_TEST_POSTGRES_DSN is not set")
	}

	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("open postgres admin pool: %v", err)
	}
	t.Cleanup(admin.Close)

	schema := fmt.Sprintf("agent_registry_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create postgres schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop postgres schema: %v", err)
		}
	})

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse postgres DSN: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("open postgres fixture pool: %v", err)
	}
	t.Cleanup(pool.Close)

	storageFS, err := mutations.ValidatedStorageFS(mutations.PostgresStorageMutations())
	if err != nil {
		t.Fatalf("validate postgres migrations: %v", err)
	}
	entries, err := fs.ReadDir(storageFS, ".")
	if err != nil {
		t.Fatalf("read postgres migrations: %v", err)
	}
	for _, entry := range entries {
		changes, err := fs.ReadFile(storageFS, entry.Name())
		if err != nil {
			t.Fatalf("read postgres migration %s: %v", entry.Name(), err)
		}
		if _, err := pool.Exec(ctx, string(changes)); err != nil {
			t.Fatalf("apply postgres migration %s: %v", entry.Name(), err)
		}
	}

	store, err := NewStorage(pool)
	if err != nil {
		t.Fatalf("new postgres registry storage: %v", err)
	}

	return &registryFixture{Storage: store, pool: pool}
}

func TestRegistry(t *testing.T) {
	conformance.Registry(t, newRegistryFixture)
}

func TestCredentials(t *testing.T) {
	conformance.Credentials(t, newRegistryFixture)
}
