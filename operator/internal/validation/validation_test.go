package validation_test

import (
	"strings"
	"testing"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func hasErrorContaining(errs field.ErrorList, substring string) bool {
	for _, err := range errs {
		if strings.Contains(err.Error(), substring) {
			return true
		}
	}

	return false
}

func plainq(mutate func(*plainqv1alpha1.PlainQ)) *plainqv1alpha1.PlainQ {
	pq := &plainqv1alpha1.PlainQ{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "plainq"},
		Spec: plainqv1alpha1.PlainQSpec{
			Version: "1.4.0",
			Storage: plainqv1alpha1.StorageSpec{Driver: plainqv1alpha1.StorageSQLite},
		},
	}

	if mutate != nil {
		mutate(pq)
	}

	return pq
}

func TestClusterRejectsPostgres(t *testing.T) {
	t.Parallel()

	pq := plainq(func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Cluster.Replicas = 3
		pq.Spec.Storage.Driver = plainqv1alpha1.StoragePostgres
		pq.Spec.Storage.Postgres.DSNSecretRef = &plainqv1alpha1.SecretKeyReference{Name: "pg", Key: "dsn"}
	})

	if errs := validation.ValidatePlainQ(pq); !hasErrorContaining(errs, "requires storage.driver=sqlite") {
		t.Fatalf("expected a driver rejection, got %v", errs)
	}
}

func TestSQLiteRejectsMultipleReplicas(t *testing.T) {
	t.Parallel()

	pq := plainq(func(pq *plainqv1alpha1.PlainQ) { pq.Spec.Replicas = 3 })

	if errs := validation.ValidatePlainQ(pq); !hasErrorContaining(errs, "single-writer") {
		t.Fatalf("expected a replica rejection, got %v", errs)
	}
}

func TestImmutableFieldsRejected(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(*plainqv1alpha1.PlainQ)
		want   string
	}{
		"storage driver": {
			mutate: func(pq *plainqv1alpha1.PlainQ) {
				pq.Spec.Storage.Driver = plainqv1alpha1.StoragePostgres
				pq.Spec.Storage.Postgres.DSNSecretRef = &plainqv1alpha1.SecretKeyReference{
					Name: "pg", Key: "dsn",
				}
			},
			want: "storage.driver is immutable",
		},
		"cluster toggle": {
			mutate: func(pq *plainqv1alpha1.PlainQ) {
				pq.Spec.Cluster.Enabled = true
				pq.Spec.Cluster.Replicas = 3
			},
			want: "cluster.enabled is immutable",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			old := plainq(nil)
			updated := plainq(tc.mutate)

			if errs := validation.ValidatePlainQUpdate(old, updated); !hasErrorContaining(errs, tc.want) {
				t.Fatalf("expected %q, got %v", tc.want, errs)
			}
		})
	}
}

func TestVolumeCannotShrink(t *testing.T) {
	t.Parallel()

	old := plainq(func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Storage.SQLite.Persistence.Size = "20Gi"
	})

	updated := plainq(func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Storage.SQLite.Persistence.Size = "10Gi"
	})

	if errs := validation.ValidatePlainQUpdate(old, updated); !hasErrorContaining(errs, "cannot shrink") {
		t.Fatalf("expected a shrink rejection, got %v", errs)
	}

	// Growing is fine.
	grown := plainq(func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Storage.SQLite.Persistence.Size = "50Gi"
	})

	if errs := validation.ValidatePlainQUpdate(old, grown); hasErrorContaining(errs, "cannot shrink") {
		t.Fatalf("growing a volume was rejected: %v", errs)
	}
}

// TestScaleInIsValidatedPerStepNotAgainstTheOriginalQuorum is the regression
// test for the rule that used to reject a safe drain outright.
func TestScaleInIsValidatedPerStepNotAgainstTheOriginalQuorum(t *testing.T) {
	t.Parallel()

	// A healthy 3-node cluster draining to 1. Quorum is recomputed after
	// every committed removal, so each step is safe even though the final
	// target of 1 is below the quorum of 2 the cluster started with.
	steps := []struct {
		currentVoters int32
		healthyVoters int32
		target        int32
	}{
		{currentVoters: 3, healthyVoters: 3, target: 2},
		{currentVoters: 2, healthyVoters: 2, target: 1},
	}

	for _, step := range steps {
		if err := validation.ValidateScaleIn(step.currentVoters, step.healthyVoters, step.target); err != nil {
			t.Fatalf("step %d->%d rejected: %v", step.currentVoters, step.target, err)
		}
	}
}

func TestScaleInRejectedWhenQuorumIsAlreadyLost(t *testing.T) {
	t.Parallel()

	// Three voters configured, only one reachable. The configuration change
	// that removes a member cannot itself be committed.
	err := validation.ValidateScaleIn(3, 1, 2)
	if err == nil {
		t.Fatal("expected a removal against a cluster short of quorum to be rejected")
	}

	if !strings.Contains(err.Error(), "needed to commit") {
		t.Fatalf("error %q does not explain why", err)
	}
}

func TestScaleInRejectsZero(t *testing.T) {
	t.Parallel()

	if err := validation.ValidateScaleIn(3, 3, 0); err == nil {
		t.Fatal("expected scaling to zero to be rejected")
	}
}

func TestQueueDeadLetterRules(t *testing.T) {
	t.Parallel()

	base := func(mutate func(*plainqv1alpha1.PlainQQueue)) *plainqv1alpha1.PlainQQueue {
		q := &plainqv1alpha1.PlainQQueue{
			ObjectMeta: metav1.ObjectMeta{Name: "orders-inbound", Namespace: "plainq"},
			Spec: plainqv1alpha1.PlainQQueueSpec{
				ServerRef: plainqv1alpha1.ServerReference{Name: "orders"},
			},
		}

		if mutate != nil {
			mutate(q)
		}

		return q
	}

	t.Run("dead letter needs a destination", func(t *testing.T) {
		t.Parallel()

		q := base(func(q *plainqv1alpha1.PlainQQueue) {
			q.Spec.EvictionPolicy = plainqv1alpha1.EvictionDeadLetter
		})

		if errs := validation.ValidatePlainQQueue(q); !hasErrorContaining(errs, "needs somewhere") {
			t.Fatalf("expected a missing-DLQ rejection, got %v", errs)
		}
	})

	t.Run("a queue cannot dead-letter into itself", func(t *testing.T) {
		t.Parallel()

		q := base(func(q *plainqv1alpha1.PlainQQueue) {
			q.Spec.EvictionPolicy = plainqv1alpha1.EvictionDeadLetter
			q.Spec.DeadLetterQueueRef = &plainqv1alpha1.LocalObjectReference{Name: "orders-inbound"}
		})

		if errs := validation.ValidatePlainQQueue(q); !hasErrorContaining(errs, "its own dead-letter") {
			t.Fatalf("expected an eviction-loop rejection, got %v", errs)
		}
	})

	t.Run("recreate needs allowDataLoss", func(t *testing.T) {
		t.Parallel()

		q := base(func(q *plainqv1alpha1.PlainQQueue) {
			q.Spec.UpdatePolicy = plainqv1alpha1.UpdateRecreate
		})

		if errs := validation.ValidatePlainQQueue(q); !hasErrorContaining(errs, "allowDataLoss") {
			t.Fatalf("expected a data-loss gate, got %v", errs)
		}
	})
}

func TestQueueRenameRejected(t *testing.T) {
	t.Parallel()

	old := &plainqv1alpha1.PlainQQueue{
		ObjectMeta: metav1.ObjectMeta{Name: "orders-inbound"},
		Spec: plainqv1alpha1.PlainQQueueSpec{
			ServerRef: plainqv1alpha1.ServerReference{Name: "orders"},
			QueueName: "orders-inbound",
		},
	}

	updated := old.DeepCopy()
	updated.Spec.QueueName = "orders-inbound-v2"

	if errs := validation.ValidatePlainQQueueUpdate(old, updated); !hasErrorContaining(errs, "immutable") {
		t.Fatalf("expected a rename rejection, got %v", errs)
	}
}

// TestNonBootstrapAccountRequiresRegistration covers the constraint the
// server imposes: signup is the only creation route and it refuses when
// self-registration is off.
func TestNonBootstrapAccountRequiresRegistration(t *testing.T) {
	t.Parallel()

	account := &plainqv1alpha1.PlainQAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: "plainq"},
		Spec: plainqv1alpha1.PlainQAccountSpec{
			ServerRef: plainqv1alpha1.ServerReference{Name: "orders"},
			Email:     "ci@example.com",
		},
	}

	errs := validation.ValidatePlainQAccount(account, false)
	if !hasErrorContaining(errs, "registration=true") {
		t.Fatalf("expected a registration rejection, got %v", errs)
	}

	// With registration on it is fine.
	if errs := validation.ValidatePlainQAccount(account, true); len(errs) != 0 {
		t.Fatalf("unexpected errors with registration enabled: %v", errs)
	}

	// The bootstrap admin goes through onboarding instead, which does not
	// consult the flag.
	account.Spec.Bootstrap = true

	if errs := validation.ValidatePlainQAccount(account, false); len(errs) != 0 {
		t.Fatalf("bootstrap account rejected: %v", errs)
	}
}

func TestDestinationMustBeExactlyOne(t *testing.T) {
	t.Parallel()

	policy := func(dest plainqv1alpha1.Destination) *plainqv1alpha1.PlainQBackupPolicy {
		return &plainqv1alpha1.PlainQBackupPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: "backups", Namespace: "plainq"},
			Spec: plainqv1alpha1.PlainQBackupPolicySpec{
				ServerRef:   plainqv1alpha1.ServerReference{Name: "orders"},
				Destination: dest,
			},
		}
	}

	t.Run("neither", func(t *testing.T) {
		t.Parallel()

		errs := validation.ValidatePlainQBackupPolicy(policy(plainqv1alpha1.Destination{}), "")
		if !hasErrorContaining(errs, "set s3 or filesystem") {
			t.Fatalf("expected a destination requirement, got %v", errs)
		}
	})

	t.Run("both", func(t *testing.T) {
		t.Parallel()

		dest := plainqv1alpha1.Destination{
			S3:         &plainqv1alpha1.S3Destination{Bucket: "b"},
			Filesystem: &plainqv1alpha1.FilesystemDestination{ExistingClaim: "c"},
		}

		errs := validation.ValidatePlainQBackupPolicy(policy(dest), "")
		if !hasErrorContaining(errs, "not both") {
			t.Fatalf("expected an ambiguity rejection, got %v", errs)
		}
	})
}

func TestEngineMustMatchDriver(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		engine plainqv1alpha1.BackupEngine
		driver plainqv1alpha1.StorageDriver
		reject bool
	}{
		"online on sqlite":         {engine: plainqv1alpha1.EngineOnline, driver: plainqv1alpha1.StorageSQLite},
		"online on postgres":       {engine: plainqv1alpha1.EngineOnline, driver: plainqv1alpha1.StoragePostgres, reject: true},
		"pg_dump on postgres":      {engine: plainqv1alpha1.EnginePostgresDump, driver: plainqv1alpha1.StoragePostgres},
		"pg_dump on sqlite":        {engine: plainqv1alpha1.EnginePostgresDump, driver: plainqv1alpha1.StorageSQLite, reject: true},
		"volumesnapshot on sqlite": {engine: plainqv1alpha1.EngineVolumeSnapshot, driver: plainqv1alpha1.StorageSQLite},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			p := &plainqv1alpha1.PlainQBackupPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "backups", Namespace: "plainq"},
				Spec: plainqv1alpha1.PlainQBackupPolicySpec{
					ServerRef:   plainqv1alpha1.ServerReference{Name: "orders"},
					Destination: plainqv1alpha1.Destination{S3: &plainqv1alpha1.S3Destination{Bucket: "b"}},
					Schedule: plainqv1alpha1.ScheduleSpec{
						Enabled: true,
						Cron:    "0 3 * * *",
						Engine:  tc.engine,
					},
				},
			}

			errs := validation.ValidatePlainQBackupPolicy(p, tc.driver)
			got := hasErrorContaining(errs, "engine needs storage.driver")

			if got != tc.reject {
				t.Fatalf("rejected=%v, want %v (errs: %v)", got, tc.reject, errs)
			}
		})
	}
}

func TestRestoreInPlaceNeedsAllowDataLoss(t *testing.T) {
	t.Parallel()

	r := &plainqv1alpha1.PlainQRestore{
		ObjectMeta: metav1.ObjectMeta{Name: "recovery", Namespace: "plainq"},
		Spec: plainqv1alpha1.PlainQRestoreSpec{
			Source: plainqv1alpha1.RestoreSource{
				BackupRef: &plainqv1alpha1.LocalObjectReference{Name: "backup"},
			},
			Target: plainqv1alpha1.RestoreTarget{
				Strategy: plainqv1alpha1.RestoreInPlace,
				InPlace: &plainqv1alpha1.InPlaceTarget{
					PlainQRef: plainqv1alpha1.LocalObjectReference{Name: "orders"},
				},
			},
		},
	}

	if errs := validation.ValidatePlainQRestore(r); !hasErrorContaining(errs, "allowDataLoss=true") {
		t.Fatalf("expected a data-loss gate, got %v", errs)
	}
}

// TestRawLocationRestoreRequiresCompleteSpec covers the case with nothing to
// inherit from: no backup object, no policy, possibly no source instance.
func TestRawLocationRestoreRequiresCompleteSpec(t *testing.T) {
	t.Parallel()

	restore := func(spec *plainqv1alpha1.PlainQSpec) *plainqv1alpha1.PlainQRestore {
		return &plainqv1alpha1.PlainQRestore{
			ObjectMeta: metav1.ObjectMeta{Name: "import", Namespace: "plainq"},
			Spec: plainqv1alpha1.PlainQRestoreSpec{
				Source: plainqv1alpha1.RestoreSource{Location: "s3://bucket/plainq.db.zst"},
				Target: plainqv1alpha1.RestoreTarget{
					Strategy:    plainqv1alpha1.RestoreNewInstance,
					NewInstance: &plainqv1alpha1.NewInstanceTarget{Name: "orders-imported", Spec: spec},
				},
			},
		}
	}

	t.Run("no spec at all", func(t *testing.T) {
		t.Parallel()

		errs := validation.ValidatePlainQRestore(restore(nil))
		if !hasErrorContaining(errs, "nothing to inherit") {
			t.Fatalf("expected a completeness requirement, got %v", errs)
		}
	})

	t.Run("partial spec names what is missing", func(t *testing.T) {
		t.Parallel()

		errs := validation.ValidatePlainQRestore(restore(&plainqv1alpha1.PlainQSpec{
			Storage: plainqv1alpha1.StorageSpec{Driver: plainqv1alpha1.StorageSQLite},
		}))

		if !hasErrorContaining(errs, "version") {
			t.Fatalf("expected the missing fields to be named, got %v", errs)
		}
	})

	t.Run("complete spec is accepted", func(t *testing.T) {
		t.Parallel()

		spec := &plainqv1alpha1.PlainQSpec{
			Version: "1.4.0",
			Storage: plainqv1alpha1.StorageSpec{
				Driver: plainqv1alpha1.StorageSQLite,
				SQLite: plainqv1alpha1.SQLiteSpec{
					Persistence: plainqv1alpha1.PersistenceSpec{Size: "20Gi"},
				},
			},
		}

		if errs := validation.ValidatePlainQRestore(restore(spec)); len(errs) != 0 {
			t.Fatalf("complete spec rejected: %v", errs)
		}
	})

	t.Run("backupRef needs no spec", func(t *testing.T) {
		t.Parallel()

		r := &plainqv1alpha1.PlainQRestore{
			ObjectMeta: metav1.ObjectMeta{Name: "recovery", Namespace: "plainq"},
			Spec: plainqv1alpha1.PlainQRestoreSpec{
				Source: plainqv1alpha1.RestoreSource{
					BackupRef: &plainqv1alpha1.LocalObjectReference{Name: "backup"},
				},
				Target: plainqv1alpha1.RestoreTarget{
					Strategy:    plainqv1alpha1.RestoreNewInstance,
					NewInstance: &plainqv1alpha1.NewInstanceTarget{Name: "orders-restored"},
				},
			},
		}

		if errs := validation.ValidatePlainQRestore(r); len(errs) != 0 {
			t.Fatalf("a backupRef restore was rejected: %v", errs)
		}
	})
}

func TestAliasClaimConflict(t *testing.T) {
	t.Parallel()

	if err := validation.ValidateAliasClaim("orders-rw", "orders-restored", "orders"); err == nil {
		t.Fatal("expected a conflict when another instance holds the alias")
	}

	// Re-claiming your own alias is a no-op, not a conflict.
	if err := validation.ValidateAliasClaim("orders-rw", "orders", "orders"); err != nil {
		t.Fatalf("re-claiming an already-held alias was rejected: %v", err)
	}

	// A free alias is claimable.
	if err := validation.ValidateAliasClaim("orders-rw", "orders", ""); err != nil {
		t.Fatalf("claiming a free alias was rejected: %v", err)
	}
}

func TestValidateCron(t *testing.T) {
	t.Parallel()

	valid := []string{
		"0 3 * * *",
		"*/15 * * * *",
		"0 */6 * * *",
		"30 2 * * 1-5",
		"0 0 1 jan *",
		"0 0 * * sun",
		"@daily",
		"0,15,30,45 * * * *",
	}

	for _, expr := range valid {
		if err := validation.ValidateCron(expr); err != nil {
			t.Errorf("ValidateCron(%q) = %v, want nil", expr, err)
		}
	}

	invalid := []string{
		"",
		"0 3 * *",            // too few fields
		"0 3 * * * *",        // too many
		"60 3 * * *",         // minute out of range
		"0 25 * * *",         // hour out of range
		"0 3 32 * *",         // day out of range
		"0 3 * 13 *",         // month out of range
		"0 3 * * 9",          // weekday out of range
		"*/0 * * * *",        // zero step
		"10-5 * * * *",       // inverted range
		"every day at three", // not cron at all
		"@sometimes",
	}

	for _, expr := range invalid {
		if err := validation.ValidateCron(expr); err == nil {
			t.Errorf("ValidateCron(%q) = nil, want an error", expr)
		}
	}
}
