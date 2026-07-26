package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BackupEngine selects how a backup is taken. The right answer differs by
// cluster and by recovery objective, so all four ship.
//
// +kubebuilder:validation:Enum=Online;VolumeSnapshot;PostgresDump;Litestream
type BackupEngine string

const (
	// EngineOnline runs VACUUM INTO through the agent sidecar: consistent,
	// does not block writers, needs no CSI snapshot support. The default for
	// scheduled backups of a SQLite instance.
	EngineOnline BackupEngine = "Online"

	// EngineVolumeSnapshot takes a CSI VolumeSnapshot and uploads from a
	// PVC created out of it. Moves the I/O off the serving pod; the copy is
	// crash-consistent rather than clean, which SQLite recovers by replaying
	// the WAL.
	EngineVolumeSnapshot BackupEngine = "VolumeSnapshot"

	// EnginePostgresDump runs pg_dump -Fc against the DSN. Auto-selected for
	// the postgres driver.
	EnginePostgresDump BackupEngine = "PostgresDump"

	// EngineLitestream is continuous WAL shipping, not a discrete run. It
	// appears here so a PlainQBackup can name the engine that produced an
	// artifact.
	EngineLitestream BackupEngine = "Litestream"
)

// VerificationMode decides how hard the operator tries to prove a backup is
// readable. A backup nobody has ever read is a hypothesis.
//
// +kubebuilder:validation:Enum=None;Checksum;Restore
type VerificationMode string

const (
	// VerifyNone skips verification.
	VerifyNone VerificationMode = "None"

	// VerifyChecksum compares the uploaded digest.
	VerifyChecksum VerificationMode = "Checksum"

	// VerifyRestore pulls the artifact back into a throwaway Job and opens
	// it: PRAGMA integrity_check for SQLite, pg_restore --list for dumps.
	VerifyRestore VerificationMode = "Restore"
)

// SourcePreference decides which cluster node a backup is taken from.
//
// +kubebuilder:validation:Enum=NonVoter;Follower;Any
type SourcePreference string

const (
	// SourceNonVoter prefers a non-voter, then a follower. Never the leader.
	SourceNonVoter SourcePreference = "NonVoter"

	// SourceFollower prefers any follower. Never the leader.
	SourceFollower SourcePreference = "Follower"

	// SourceAny allows the leader when nothing else is available.
	SourceAny SourcePreference = "Any"
)

// ConcurrencyPolicy mirrors the CronJob field of the same name.
//
// +kubebuilder:validation:Enum=Allow;Forbid;Replace
type ConcurrencyPolicy string

const (
	ConcurrencyAllow   ConcurrencyPolicy = "Allow"
	ConcurrencyForbid  ConcurrencyPolicy = "Forbid"
	ConcurrencyReplace ConcurrencyPolicy = "Replace"
)

// PlainQBackupPolicySpec is the desired backup regime for one instance.
type PlainQBackupPolicySpec struct {
	// ServerRef points at the instance to back up.
	ServerRef ServerReference `json:"serverRef"`

	// Continuous configures WAL shipping through a Litestream sidecar.
	//
	// +optional
	Continuous ContinuousSpec `json:"continuous,omitempty"`

	// Schedule configures periodic whole-database backups.
	//
	// +optional
	Schedule ScheduleSpec `json:"schedule,omitempty"`

	// Destination is where artifacts are written.
	Destination Destination `json:"destination"`

	// Compression applied before upload.
	//
	// +kubebuilder:default=zstd
	// +optional
	Compression Compression `json:"compression,omitempty"`

	// Encryption at rest, on top of whatever the destination does.
	//
	// +optional
	Encryption EncryptionSpec `json:"encryption,omitempty"`

	// Retention prunes artifacts and the PlainQBackup objects naming them.
	//
	// +optional
	Retention RetentionSpec `json:"retention,omitempty"`

	// Verify decides how hard the operator tries to prove readability.
	//
	// +kubebuilder:default=Checksum
	// +optional
	Verify VerificationMode `json:"verify,omitempty"`

	// Source selects which cluster node backups are taken from.
	//
	// +optional
	Source SourceSpec `json:"source,omitempty"`

	// Resources for the backup agent and Jobs.
	//
	// +optional
	Resources PodResources `json:"resources,omitempty"`

	// PodTemplate carries scheduling constraints for backup Jobs.
	//
	// +optional
	PodTemplate BackupPodTemplate `json:"podTemplate,omitempty"`
}

// ContinuousSpec configures WAL shipping.
type ContinuousSpec struct {
	// Enabled injects the Litestream sidecar.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// SyncInterval between WAL pushes. This is the practical RPO.
	//
	// +kubebuilder:default="10s"
	// +optional
	SyncInterval string `json:"syncInterval,omitempty"`

	// SnapshotInterval between full snapshots at the destination.
	//
	// +kubebuilder:default="1h"
	// +optional
	SnapshotInterval string `json:"snapshotInterval,omitempty"`

	// Resources for the sidecar.
	//
	// +optional
	Resources PodResources `json:"resources,omitempty"`
}

// ScheduleSpec configures periodic backups.
type ScheduleSpec struct {
	// Enabled renders the CronJob.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Cron expression in standard five-field form.
	//
	// +optional
	Cron string `json:"cron,omitempty"`

	// TimeZone the expression is evaluated in.
	//
	// +optional
	TimeZone string `json:"timeZone,omitempty"`

	// Engine used for each run.
	//
	// +kubebuilder:default=Online
	// +optional
	Engine BackupEngine `json:"engine,omitempty"`

	// StartingDeadlineSeconds before a missed run is abandoned.
	//
	// +optional
	StartingDeadlineSeconds *int64 `json:"startingDeadlineSeconds,omitempty"`

	// ConcurrencyPolicy for overlapping runs.
	//
	// +kubebuilder:default=Forbid
	// +optional
	ConcurrencyPolicy ConcurrencyPolicy `json:"concurrencyPolicy,omitempty"`

	// Suspend pauses the schedule without deleting it.
	//
	// +optional
	Suspend bool `json:"suspend,omitempty"`

	// Timeout for one run.
	//
	// +kubebuilder:default="1h"
	// +optional
	Timeout string `json:"timeout,omitempty"`

	// SourceSyncTimeout bounds how long the operator waits for the chosen
	// source node to apply the leader's committed log before copying.
	//
	// A reachable follower can lag while the cluster still reports healthy:
	// ClusterStatus.Healthy is leader-present plus reachable-voter quorum
	// and says nothing about applied index. Copying such a node produces an
	// artifact that silently omits acknowledged writes.
	//
	// +kubebuilder:default="2m"
	// +optional
	SourceSyncTimeout string `json:"sourceSyncTimeout,omitempty"`
}

// RetentionSpec prunes old backups. The tiers are grandfather-father-son, so
// an aggressive KeepLast cannot delete the only monthly you have.
type RetentionSpec struct {
	// KeepLast retains the N most recent backups.
	//
	// +optional
	KeepLast int32 `json:"keepLast,omitempty"`

	// KeepDaily retains the newest backup of each of the last N days.
	//
	// +optional
	KeepDaily int32 `json:"keepDaily,omitempty"`

	// KeepWeekly retains the newest backup of each of the last N weeks.
	//
	// +optional
	KeepWeekly int32 `json:"keepWeekly,omitempty"`

	// KeepMonthly retains the newest backup of each of the last N months.
	//
	// +optional
	KeepMonthly int32 `json:"keepMonthly,omitempty"`

	// MaxAge deletes anything older, regardless of the tiers above.
	//
	// +optional
	MaxAge string `json:"maxAge,omitempty"`
}

// SourceSpec selects which cluster node backups are taken from.
type SourceSpec struct {
	// Prefer decides the selection order.
	//
	// +kubebuilder:default=NonVoter
	// +optional
	Prefer SourcePreference `json:"prefer,omitempty"`
}

// PodResources is a resource requirement expressed as plain strings, so the
// backup surface does not drag corev1 quantity parsing into every field.
type PodResources struct {
	// Requests for the container.
	//
	// +optional
	Requests map[string]string `json:"requests,omitempty"`

	// Limits for the container.
	//
	// +optional
	Limits map[string]string `json:"limits,omitempty"`
}

// BackupPodTemplate carries scheduling constraints for backup Jobs.
type BackupPodTemplate struct {
	// NodeSelector for backup Jobs.
	//
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Annotations for backup Job pods.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels for backup Job pods.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// PlainQBackupPolicyStatus is the observed state of a backup regime.
type PlainQBackupPolicyStatus struct {
	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// LastSuccessfulBackup is when a run last completed successfully.
	//
	// +optional
	LastSuccessfulBackup *metav1.Time `json:"lastSuccessfulBackup,omitempty"`

	// LastBackup summarizes the most recent run, successful or not.
	//
	// +optional
	LastBackup *LastBackupStatus `json:"lastBackup,omitempty"`

	// Continuous reports on WAL shipping.
	//
	// +optional
	Continuous *ContinuousStatus `json:"continuous,omitempty"`

	// BackupsRetained is how many artifacts survive retention.
	//
	// +optional
	BackupsRetained int32 `json:"backupsRetained,omitempty"`

	// TotalSize of retained artifacts.
	//
	// +optional
	TotalSize string `json:"totalSize,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ContinuousStatus reports on WAL shipping.
type ContinuousStatus struct {
	// Healthy reports whether replication is keeping up.
	//
	// +optional
	Healthy bool `json:"healthy,omitempty"`

	// Lag behind the primary.
	//
	// +optional
	Lag string `json:"lag,omitempty"`

	// LastSync timestamp.
	//
	// +optional
	LastSync *metav1.Time `json:"lastSync,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqbp,categories=plainq
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule.cron`
// +kubebuilder:printcolumn:name="Last Success",type=date,JSONPath=`.status.lastSuccessfulBackup`
// +kubebuilder:printcolumn:name="Retained",type=integer,JSONPath=`.status.backupsRetained`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQBackupPolicy is a backup regime for one PlainQ instance.
type PlainQBackupPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQBackupPolicySpec   `json:"spec,omitempty"`
	Status PlainQBackupPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlainQBackupPolicyList contains a list of PlainQBackupPolicy.
type PlainQBackupPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQBackupPolicy `json:"items"`
}
