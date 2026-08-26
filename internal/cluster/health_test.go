package cluster

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	hraft "github.com/hashicorp/raft"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

func TestPreGuardRaftStoreInitializesVersionExactlyOnce(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()

	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.Check(); err != nil {
		t.Fatalf("new health Check() = %v", err)
	}
	version, err := stable.Get(replicaApplyGuardVersionKey)
	if err != nil {
		t.Fatalf("read guard version: %v", err)
	}
	if string(version) != replicaApplyGuardVersion {
		t.Fatalf("guard version = %q, want %q", version, replicaApplyGuardVersion)
	}

	// Reopening must use the stable version and preserve the existing clean
	// marker rather than treating the replica as a fresh upgrade.
	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); err != nil {
		t.Fatalf("reopened health Check() = %v", err)
	}
}

func TestReplicaApplyGuardMissingOnRestartQuarantines(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := os.Remove(health.cleanPath); err != nil {
		t.Fatalf("remove clean marker: %v", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("reopened Check() = %v, want %v", err, pqerr.ErrUnavailable)
	}
}

func TestExistingRaftGuardVersionWithAllSidecarsMissingQuarantines(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	if err := stable.Set(replicaApplyGuardVersionKey, []byte(replicaApplyGuardVersion)); err != nil {
		t.Fatalf("seed guard version: %v", err)
	}

	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("Check() = %v, want %v", err, pqerr.ErrUnavailable)
	}
	if _, err := os.Stat(filepath.Join(dir, replicaApplyCleanFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clean marker stat = %v, want absent", err)
	}
}

func TestReplicaQuarantineMarkerSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}
	partial := errors.New("replica-local partial publish")
	if err := health.Fail(partial); err != nil {
		t.Fatalf("Fail() persistence error = %v", err)
	}
	if err := health.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("Check() = %v, want unavailable", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("reopened Check() = %v, want unavailable", err)
	}
}

func TestSuccessfulPublishRestoresReplicaApplyGuard(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}
	if _, err := os.Stat(health.dirtyPath); err != nil {
		t.Fatalf("dirty marker after begin: %v", err)
	}
	if err := health.FinishPublishApply(); err != nil {
		t.Fatalf("FinishPublishApply() = %v", err)
	}
	if _, err := os.Stat(health.cleanPath); err != nil {
		t.Fatalf("clean marker after finish: %v", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); err != nil {
		t.Fatalf("reopened Check() = %v", err)
	}
}

func TestSuccessfulSnapshotRestoreClearsReplicaQuarantine(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}
	if err := health.Fail(errors.New("partial")); err != nil {
		t.Fatalf("Fail() = %v", err)
	}
	if err := health.Recover(); err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	if err := health.Check(); err != nil {
		t.Fatalf("Check() after recovery = %v", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); err != nil {
		t.Fatalf("reopened Check() = %v", err)
	}
}

func TestReplicaApplyGuardFinishAndDiagnosticFailuresStayQuarantinedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}

	syncErr := errors.New("directory fsync failed")
	health.syncDir = func(string) error { return syncErr }
	if err := health.FinishPublishApply(); !errors.Is(err, syncErr) {
		t.Fatalf("FinishPublishApply() = %v, want sync error", err)
	}
	if _, err := os.Stat(health.dirtyPath); err != nil {
		t.Fatalf("dirty marker after finish rollback = %v", err)
	}

	markerErr := errors.New("diagnostic marker write failed")
	health.writeMarker = func(string, string) error { return markerErr }
	if err := health.Fail(errors.New("uncertain publish")); !errors.Is(err, markerErr) {
		t.Fatalf("Fail() = %v, want marker error", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("reopened Check() = %v, want unavailable", err)
	}
}

func TestReplicaQuarantineMarkerWriteFailureStaysUnreadyAfterRestart(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}
	markerErr := errors.New("diagnostic disk failure")
	health.writeMarker = func(string, string) error { return markerErr }
	if err := health.Fail(errors.New("partial")); !errors.Is(err, markerErr) {
		t.Fatalf("Fail() = %v, want marker error", err)
	}

	reopened, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("reopen newReplicaHealth() error = %v", err)
	}
	if err := reopened.Check(); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("reopened Check() = %v, want unavailable", err)
	}
}

func TestServingTokenRejectsFailRecoverABA(t *testing.T) {
	dir := t.TempDir()
	stable := hraft.NewInmemStore()
	health, err := newReplicaHealth(dir, stable)
	if err != nil {
		t.Fatalf("newReplicaHealth() error = %v", err)
	}
	token, err := health.ServingToken()
	if err != nil {
		t.Fatalf("ServingToken() = %v", err)
	}
	if err := health.BeginPublishApply(); err != nil {
		t.Fatalf("BeginPublishApply() = %v", err)
	}
	if err := health.Fail(errors.New("partial")); err != nil {
		t.Fatalf("Fail() = %v", err)
	}
	if err := health.Recover(); err != nil {
		t.Fatalf("Recover() = %v", err)
	}
	if err := health.CheckServingToken(token); !errors.Is(err, pqerr.ErrUnavailable) {
		t.Fatalf("CheckServingToken(old) = %v, want unavailable", err)
	}
	newToken, err := health.ServingToken()
	if err != nil {
		t.Fatalf("ServingToken(after recovery) = %v", err)
	}
	if newToken == token {
		t.Fatalf("serving token = %d before and after fail/recover", token)
	}
	if err := health.CheckServingToken(newToken); err != nil {
		t.Fatalf("CheckServingToken(new) = %v", err)
	}
}
