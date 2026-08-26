package cluster

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	hraft "github.com/hashicorp/raft"
	boltstore "github.com/hashicorp/raft-boltdb/v2"
	"github.com/heartwilltell/hc"
	"github.com/marsolab/plainq/internal/shared/pqerr"
)

var _ hc.HealthChecker = (*Node)(nil)

const (
	replicaApplyCleanFile     = "replica-apply-clean"
	replicaApplyDirtyFile     = "replica-apply-dirty"
	replicaQuarantinedFile    = "replica-quarantined"
	replicaApplyGuardVersion  = "1"
	replicaMarkerContents     = "plainq replica health marker\n"
	replicaQuarantineContents = "plainq replica quarantined; restore a verified snapshot or wipe and reseed the replica\n"
)

var replicaApplyGuardVersionKey = []byte("plainq/replica-apply-guard-version")

// Health implements hc.HealthChecker. Quarantine is checked before physical
// storage, and physical storage before quorum, so the most local actionable
// failure is reported first.
func (n *Node) Health(ctx context.Context) error {
	if err := n.replicaHealth.Check(); err != nil {
		return err
	}
	if err := n.localHealth.Health(ctx); err != nil {
		return fmt.Errorf("cluster replica storage: %w", err)
	}
	if !n.Status().Healthy {
		return fmt.Errorf("%w: cluster has no reachable write quorum", pqerr.ErrUnavailable)
	}

	return nil
}

type replicaFault struct {
	err error
}

// replicaHealth is the one fail-closed latch shared by every public data path
// on a clustered replica. The atomic pointer closes serving immediately; the
// marker protocol keeps it closed through a process restart.
type replicaHealth struct {
	fault      atomic.Pointer[replicaFault]
	generation atomic.Uint64

	cleanPath      string
	dirtyPath      string
	quarantinePath string

	markerMu sync.Mutex

	writeMarker func(string, string) error
	rename      func(string, string) error
	remove      func(string) error
	syncDir     func(string) error
}

func newReplicaHealth(dataDir string, stable hraft.StableStore) (*replicaHealth, error) {
	if stable == nil {
		return nil, errors.New("replica health: raft stable store is required")
	}
	if dataDir == "" {
		return nil, errors.New("replica health: data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create replica health directory %q: %w", dataDir, err)
	}

	h := &replicaHealth{
		cleanPath:      filepath.Join(dataDir, replicaApplyCleanFile),
		dirtyPath:      filepath.Join(dataDir, replicaApplyDirtyFile),
		quarantinePath: filepath.Join(dataDir, replicaQuarantinedFile),
		writeMarker:    writeReplicaMarker,
		rename:         os.Rename,
		remove:         os.Remove,
		syncDir:        syncReplicaDirectory,
	}

	version, err := stable.Get(replicaApplyGuardVersionKey)
	if err != nil && !errors.Is(err, boltstore.ErrKeyNotFound) && err.Error() != boltstore.ErrKeyNotFound.Error() {
		return nil, fmt.Errorf("read replica apply guard version: %w", err)
	}
	if err != nil {
		version = nil
	}

	clean, err := markerExists(h.cleanPath)
	if err != nil {
		return nil, err
	}
	dirty, err := markerExists(h.dirtyPath)
	if err != nil {
		return nil, err
	}
	quarantined, err := markerExists(h.quarantinePath)
	if err != nil {
		return nil, err
	}

	switch string(version) {
	case "":
		// This is the only upgrade path from replicas created before the guard
		// existed. A dirty or quarantine file proves this is not a fresh
		// upgrade, even if the stable bit was not durably written yet.
		if dirty || quarantined {
			h.latch(errors.New("replica apply guard upgrade found an unsafe marker"))
			return h, nil
		}
		if !clean {
			if err := h.writeMarker(h.cleanPath, replicaMarkerContents); err != nil {
				return nil, fmt.Errorf("initialize replica apply guard: %w", err)
			}
		}
		if err := stable.Set(replicaApplyGuardVersionKey, []byte(replicaApplyGuardVersion)); err != nil {
			return nil, fmt.Errorf("persist replica apply guard version: %w", err)
		}

	case replicaApplyGuardVersion:
		if !clean || dirty || quarantined {
			h.latch(errors.New("replica apply guard is not clean"))
		}

	default:
		return nil, fmt.Errorf("unsupported replica apply guard version %q", version)
	}

	return h, nil
}

// Check returns typed temporary unavailability after the first fault. It does
// not expose the underlying storage error to public callers.
func (h *replicaHealth) Check() error {
	if h == nil {
		return fmt.Errorf("%w: replica health is not initialized", pqerr.ErrUnavailable)
	}
	if h.fault.Load() == nil {
		return nil
	}

	return fmt.Errorf("%w: clustered replica is quarantined", pqerr.ErrUnavailable)
}

func (h *replicaHealth) Quarantined() bool {
	return h == nil || h.fault.Load() != nil
}

// ServingToken captures the current health generation for a local read. The
// caller must validate it after the read so a Fail/Recover ABA cannot let data
// observed across a quarantine boundary escape.
func (h *replicaHealth) ServingToken() (uint64, error) {
	if err := h.Check(); err != nil {
		return 0, err
	}
	token := h.generation.Load()
	if err := h.CheckServingToken(token); err != nil {
		return 0, err
	}

	return token, nil
}

func (h *replicaHealth) CheckServingToken(token uint64) error {
	if h == nil || h.generation.Load() != token {
		return fmt.Errorf("%w: replica health changed while serving the request", pqerr.ErrUnavailable)
	}
	if err := h.Check(); err != nil {
		return err
	}
	if h.generation.Load() != token {
		return fmt.Errorf("%w: replica health changed while serving the request", pqerr.ErrUnavailable)
	}

	return nil
}

// BeginPublishApply durably records that a committed publish is about to
// touch local storage. Nothing may mutate storage if this step fails.
func (h *replicaHealth) BeginPublishApply() error {
	if err := h.Check(); err != nil {
		return err
	}

	h.markerMu.Lock()
	defer h.markerMu.Unlock()

	if err := h.Check(); err != nil {
		return err
	}
	if err := h.rename(h.cleanPath, h.dirtyPath); err != nil {
		return fmt.Errorf("rename clean replica apply guard to dirty: %w", err)
	}
	if err := h.syncDir(filepath.Dir(h.cleanPath)); err != nil {
		return fmt.Errorf("sync dirty replica apply guard directory: %w", err)
	}

	return nil
}

// FinishPublishApply marks a deterministic, fully applied publish clean.
func (h *replicaHealth) FinishPublishApply() error {
	h.markerMu.Lock()
	defer h.markerMu.Unlock()

	if err := h.rename(h.dirtyPath, h.cleanPath); err != nil {
		return fmt.Errorf("rename dirty replica apply guard to clean: %w", err)
	}
	if err := h.syncDir(filepath.Dir(h.cleanPath)); err != nil {
		// Keep the restart state fail-closed if the clean transition itself
		// could not be made durable.
		rollbackErr := h.rename(h.cleanPath, h.dirtyPath)
		if rollbackErr == nil {
			rollbackErr = h.syncDir(filepath.Dir(h.cleanPath))
		}
		return errors.Join(
			fmt.Errorf("sync clean replica apply guard directory: %w", err),
			wrapIfNonNil("restore dirty replica apply guard", rollbackErr),
		)
	}

	return nil
}

// Fail closes serving before attempting any diagnostic I/O. The missing clean
// marker created by BeginPublishApply is the safety record; this file is for
// operators and may fail independently without reopening the latch.
func (h *replicaHealth) Fail(cause error) error {
	if cause == nil {
		cause = errors.New("replica state-machine result was non-deterministic")
	}
	if !h.fault.CompareAndSwap(nil, &replicaFault{err: cause}) {
		return nil
	}
	h.generation.Add(1)

	h.markerMu.Lock()
	defer h.markerMu.Unlock()

	if err := h.writeMarker(h.quarantinePath, replicaQuarantineContents); err != nil {
		return fmt.Errorf("persist replica quarantine marker: %w", err)
	}

	return nil
}

// Recover reopens serving only after the caller has committed and inventoried
// a verified snapshot. Every filesystem transition completes before the
// in-memory latch is cleared.
func (h *replicaHealth) Recover() error {
	h.markerMu.Lock()
	defer h.markerMu.Unlock()

	// Ensure an unexpected recovery error cannot leave a previously healthy
	// latch serving with an incomplete marker set.
	h.latch(errors.New("replica recovery is in progress"))

	if err := h.writeMarker(h.cleanPath, replicaMarkerContents); err != nil {
		return fmt.Errorf("write recovered replica apply guard: %w", err)
	}
	if err := removeReplicaMarker(h.remove, h.dirtyPath); err != nil {
		return fmt.Errorf("remove dirty replica apply guard: %w", err)
	}
	if err := removeReplicaMarker(h.remove, h.quarantinePath); err != nil {
		return fmt.Errorf("remove replica quarantine marker: %w", err)
	}
	if err := h.syncDir(filepath.Dir(h.cleanPath)); err != nil {
		return errors.Join(
			fmt.Errorf("sync recovered replica health directory: %w", err),
			wrapIfNonNil("re-quarantine replica after failed recovery", h.requarantineFailedRecovery()),
		)
	}

	h.generation.Add(1)
	h.fault.Store(nil)

	return nil
}

// requarantineFailedRecovery establishes two independent fail-closed records:
// the dirty apply guard and the diagnostic quarantine marker. Either durable
// record is sufficient to keep a restarted process unavailable. Both paths
// are attempted so a failure in one does not prevent the other from restoring
// restart safety, and every diagnostic is returned to the caller.
func (h *replicaHealth) requarantineFailedRecovery() error {
	var rollbackErrs []error
	dir := filepath.Dir(h.cleanPath)

	if err := h.rename(h.cleanPath, h.dirtyPath); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("rename recovered clean guard to dirty: %w", err))
	} else if err := h.syncDir(dir); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("sync restored dirty guard: %w", err))
	}

	if err := h.writeMarker(h.quarantinePath, replicaQuarantineContents); err != nil {
		rollbackErrs = append(rollbackErrs, fmt.Errorf("restore quarantine marker: %w", err))
	}

	return errors.Join(rollbackErrs...)
}

func (h *replicaHealth) latch(err error) {
	if h.fault.CompareAndSwap(nil, &replicaFault{err: err}) {
		h.generation.Add(1)
	}
}

func markerExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}

	return false, fmt.Errorf("inspect replica health marker %q: %w", path, err)
}

func writeReplicaMarker(path, contents string) (retErr error) {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".replica-marker-*")
	if err != nil {
		return fmt.Errorf("create temporary marker for %q: %w", path, err)
	}
	temporaryName := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary marker %q: %w", temporaryName, err))
		}
	}()

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("set marker permissions: %w", err)
	}
	if _, err := io.WriteString(temporary, contents); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write marker: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync marker: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close marker: %w", err)
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("install marker %q: %w", path, err)
	}
	if err := syncReplicaDirectory(dir); err != nil {
		return fmt.Errorf("sync marker directory %q: %w", dir, err)
	}

	return nil
}

func syncReplicaDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}

	return dir.Close()
}

func removeReplicaMarker(remove func(string) error, path string) error {
	if err := remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}

func wrapIfNonNil(message string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", message, err)
}
