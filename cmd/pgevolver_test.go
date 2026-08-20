package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/marsolab/plainq/internal/server/mutations"
)

func openPGEvolverTestPool(t *testing.T) *pgxpool.Pool {
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

	schema := fmt.Sprintf("plainq_evolver_%d", time.Now().UnixNano())
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

	return pool
}

func TestPGEvolverRollsBackMigrationAndVersionOnInjectedCrash(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	migrations := fstest.MapFS{
		"001_committed.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE committed (id integer PRIMARY KEY);
			INSERT INTO committed (id) VALUES (1);
		`)},
		"002_crash.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE rolled_back (id integer PRIMARY KEY);
			INSERT INTO rolled_back (id) VALUES (2);
			DO $$ BEGIN RAISE EXCEPTION 'injected migration crash'; END $$;
		`)},
		"003_never.sql": &fstest.MapFile{Data: []byte(`CREATE TABLE never_applied (id integer PRIMARY KEY);`)},
	}

	err := newPgEvolver(pool, migrations).MutateSchema()
	if err == nil {
		t.Fatal("mutate schema: want injected crash, got nil")
	}

	ctx := context.Background()
	var version int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if version != 1 {
		t.Fatalf("schema version = %d, want 1", version)
	}

	var committedCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM committed`).Scan(&committedCount); err != nil {
		t.Fatalf("read committed migration: %v", err)
	}
	if committedCount != 1 {
		t.Fatalf("committed row count = %d, want 1", committedCount)
	}

	for _, table := range []string{"rolled_back", "never_applied"} {
		var relation *string
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1)::text`, table).Scan(&relation); err != nil {
			t.Fatalf("look up %s: %v", table, err)
		}
		if relation != nil {
			t.Fatalf("table %s survived failed migration", table)
		}
	}
}

func TestPGEvolverAdvisoryLockSerializesConcurrentRunners(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	migrations := fstest.MapFS{
		"001_race.sql": &fstest.MapFile{Data: []byte(`
			CREATE TABLE migration_race (id integer PRIMARY KEY);
			INSERT INTO migration_race (id) VALUES (1);
			SELECT pg_sleep(0.1);
		`)},
	}

	start := make(chan struct{})
	errorsByRunner := make(chan error, 2)
	var runners sync.WaitGroup
	for range 2 {
		runners.Add(1)
		go func() {
			defer runners.Done()
			<-start
			errorsByRunner <- newPgEvolver(pool, migrations).MutateSchema()
		}()
	}
	close(start)
	runners.Wait()
	close(errorsByRunner)

	for err := range errorsByRunner {
		if err != nil {
			t.Fatalf("concurrent schema mutation: %v", err)
		}
	}

	ctx := context.Background()
	var version, rows int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read schema version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM migration_race`).Scan(&rows); err != nil {
		t.Fatalf("count migration rows: %v", err)
	}
	if version != 1 || rows != 1 {
		t.Fatalf("migration state = version %d rows %d, want version 1 rows 1", version, rows)
	}
}

func TestPGEvolverUpgradeFromVersionFourPreservesData(t *testing.T) {
	pool := openPGEvolverTestPool(t)
	allMutations := mutations.PostgresStorageMutations()
	versionFour := make(fstest.MapFS, 4)
	for _, name := range []string{
		"001_schema.sql",
		"002_user.sql",
		"003_organizations.sql",
		"004_pubsub.sql",
	} {
		data, err := fs.ReadFile(allMutations, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		versionFour[name] = &fstest.MapFile{Data: data}
	}

	if err := newPgEvolver(pool, versionFour).MutateSchema(); err != nil {
		t.Fatalf("apply version-four schema: %v", err)
	}

	const (
		orgID   = "01J00000000000000000000001"
		userID  = "01J00000000000000000000002"
		queueID = "01J00000000000000000000003"
		topicID = "01J00000000000000000000004"
	)
	statements := []struct {
		query string
		args  []any
	}{
		{
			query: `INSERT INTO organizations (org_id, org_code, org_name) VALUES ($1, 'upgrade', 'Upgrade Tenant')`,
			args:  []any{orgID},
		},
		{
			query: `INSERT INTO users (user_id, email, password, org_id) VALUES ($1, 'upgrade@example.test', 'existing-hash', $2)`,
			args:  []any{userID, orgID},
		},
		{
			query: `INSERT INTO queue_properties (queue_id, queue_name, retention_period_seconds, visibility_timeout_seconds, max_receive_attempts) VALUES ($1, 'upgrade-queue', 3600, 30, 5)`,
			args:  []any{queueID},
		},
		{
			query: `INSERT INTO topic_properties (topic_id, topic_name) VALUES ($1, 'upgrade-topic')`,
			args:  []any{topicID},
		},
		{
			query: `INSERT INTO topic_subscriptions (subscription_id, topic_id, queue_id) VALUES ('01J00000000000000000000005', $1, $2)`,
			args:  []any{topicID, queueID},
		},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(context.Background(), statement.query, statement.args...); err != nil {
			t.Fatalf("seed version-four data: %v", err)
		}
	}

	if err := newPgEvolver(pool, allMutations).MutateSchema(); err != nil {
		t.Fatalf("upgrade version-four schema: %v", err)
	}

	ctx := context.Background()
	var version, users, subscriptions int
	if err := pool.QueryRow(ctx, `SELECT version FROM schema_version WHERE id = 0`).Scan(&version); err != nil {
		t.Fatalf("read upgraded schema version: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE user_id = $1 AND org_id = $2`, userID, orgID).Scan(&users); err != nil {
		t.Fatalf("read preserved user: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM topic_subscriptions WHERE topic_id = $1 AND queue_id = $2`, topicID, queueID).Scan(&subscriptions); err != nil {
		t.Fatalf("read preserved subscription: %v", err)
	}
	if version != 5 || users != 1 || subscriptions != 1 {
		t.Fatalf("upgrade state = version %d users %d subscriptions %d, want version 5 users 1 subscriptions 1", version, users, subscriptions)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO agents (
		agent_id, tenant_id, agent_name, status, auth_version, created_by_kind,
		created_by_id, created_at_ns, updated_at_ns
	) VALUES ($1, $2, 'upgrade-agent', 1, 1, 'system', 'upgrade-test', 1, 1)`, "01J00000000000000000000006", orgID); err != nil {
		t.Fatalf("write new version-five table after upgrade: %v", err)
	}
}
