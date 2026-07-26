package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// BackupPhase is the lifecycle of one backup run.
//
// +kubebuilder:validation:Enum=Pending;Running;Succeeded;Failed;Deleting
type BackupPhase string

const (
	BackupPending   BackupPhase = "Pending"
	BackupRunning   BackupPhase = "Running"
	BackupSucceeded BackupPhase = "Succeeded"
	BackupFailed    BackupPhase = "Failed"
	BackupDeleting  BackupPhase = "Deleting"
)

// PlainQBackupSpec is one backup run: created by a policy's CronJob, or by
// hand for an ad-hoc backup before an upgrade.
type PlainQBackupSpec struct {
	// ServerRef points at the instance to back up.
	ServerRef ServerReference `json:"serverRef"`

	// PolicyRef seeds the effective configuration from a policy.
	//
	// +optional
	PolicyRef *LocalObjectReference `json:"policyRef,omitempty"`

	// Engine overrides the policy's engine for this run.
	//
	// +optional
	Engine BackupEngine `json:"engine,omitempty"`

	// Destination overrides the policy's destination.
	//
	// +optional
	Destination *Destination `json:"destination,omitempty"`

	// Compression overrides the policy's compression.
	//
	// +optional
	Compression Compression `json:"compression,omitempty"`

	// Encryption overrides the policy's encryption.
	//
	// +optional
	Encryption *EncryptionSpec `json:"encryption,omitempty"`

	// TTL after which this object is garbage collected. Empty leaves it to
	// the policy's retention.
	//
	// +optional
	TTL string `json:"ttl,omitempty"`

	// DeletionPolicy decides whether deleting this object deletes the
	// artifact at the destination.
	//
	// +kubebuilder:default=Delete
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// PlainQBackupStatus is the observed state of one backup run.
type PlainQBackupStatus struct {
	// Phase of the run.
	//
	// +optional
	Phase BackupPhase `json:"phase,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Engine that produced the artifact.
	//
	// +optional
	Engine BackupEngine `json:"engine,omitempty"`

	// SourceNode the artifact was copied from.
	//
	// +optional
	SourceNode string `json:"sourceNode,omitempty"`

	// Consensus records how current the copy was, in log terms.
	//
	// +optional
	Consensus *ConsensusStatus `json:"consensus,omitempty"`

	// StartedAt timestamp.
	//
	// +optional
	StartedAt *metav1.Time `json:"startedAt,omitempty"`

	// CompletedAt timestamp.
	//
	// +optional
	CompletedAt *metav1.Time `json:"completedAt,omitempty"`

	// Duration of the run.
	//
	// +optional
	Duration string `json:"duration,omitempty"`

	// Size of the database before compression.
	//
	// +optional
	Size string `json:"size,omitempty"`

	// CompressedSize of the stored artifact.
	//
	// +optional
	CompressedSize string `json:"compressedSize,omitempty"`

	// Location is the artifact URI.
	//
	// +optional
	Location string `json:"location,omitempty"`

	// Checksum of the stored artifact.
	//
	// +optional
	Checksum *ChecksumSpec `json:"checksum,omitempty"`

	// ServerVersion that produced the database.
	//
	// +optional
	ServerVersion string `json:"serverVersion,omitempty"`

	// StorageDriver of the source instance.
	//
	// +optional
	StorageDriver StorageDriver `json:"storageDriver,omitempty"`

	// Verification result.
	//
	// +optional
	Verification *VerificationStatus `json:"verification,omitempty"`

	// EffectiveConfig is everything needed to read this artifact back,
	// frozen before the run started and never updated afterwards.
	//
	// A run that remembered only PolicyRef would stop being restorable the
	// moment that policy was edited or deleted: a later restore would
	// resolve today's bucket, endpoint, encryption identity and compression
	// rather than the ones the artifact was written with. Rotating an S3
	// endpoint would quietly invalidate every historical backup.
	//
	// Secret references are frozen, not secret values.
	//
	// +optional
	EffectiveConfig *EffectiveBackupConfig `json:"effectiveConfig,omitempty"`

	// Message explains a failure.
	//
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// ConsensusStatus records how current a copy was, in log terms.
type ConsensusStatus struct {
	// LeaderCommitIndex captured before the copy began.
	//
	// +optional
	LeaderCommitIndex uint64 `json:"leaderCommitIndex,omitempty"`

	// SourceAppliedIndex the source node had reached when it was copied.
	// Equal to or greater than LeaderCommitIndex on a correct run.
	//
	// +optional
	SourceAppliedIndex uint64 `json:"sourceAppliedIndex,omitempty"`
}

// VerificationStatus records the outcome of a verification pass.
type VerificationStatus struct {
	// Result is Passed, Failed or Skipped.
	//
	// +optional
	Result string `json:"result,omitempty"`

	// At is when verification ran.
	//
	// +optional
	At *metav1.Time `json:"at,omitempty"`

	// Message explains a failure.
	//
	// +optional
	Message string `json:"message,omitempty"`
}

// EffectiveBackupConfig is the frozen, self-contained record of how an
// artifact was written and what it came from.
type EffectiveBackupConfig struct {
	// Engine used.
	//
	// +optional
	Engine BackupEngine `json:"engine,omitempty"`

	// Compression applied.
	//
	// +optional
	Compression Compression `json:"compression,omitempty"`

	// Encryption applied, by reference.
	//
	// +optional
	Encryption *EncryptionSpec `json:"encryption,omitempty"`

	// Destination the artifact was written to.
	//
	// +optional
	Destination *Destination `json:"destination,omitempty"`

	// Source describes the instance shape, so a restore can stand an
	// instance up from the artifact alone.
	//
	// +optional
	Source *BackupSourceConfig `json:"source,omitempty"`
}

// BackupSourceConfig is the shape of the instance a backup came from: enough
// to provision a compatible one from scratch.
type BackupSourceConfig struct {
	// StorageDriver of the source.
	//
	// +optional
	StorageDriver StorageDriver `json:"storageDriver,omitempty"`

	// ServerVersion of the source.
	//
	// +optional
	ServerVersion string `json:"serverVersion,omitempty"`

	// SQLitePath inside the container.
	//
	// +optional
	SQLitePath string `json:"sqlitePath,omitempty"`

	// VolumeSize of the source's data volume.
	//
	// +optional
	VolumeSize string `json:"volumeSize,omitempty"`

	// Cluster shape of the source.
	//
	// +optional
	Cluster *BackupSourceCluster `json:"cluster,omitempty"`
}

// BackupSourceCluster is the cluster shape of a backup's source.
type BackupSourceCluster struct {
	// Enabled reports whether the source was clustered.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Replicas the source ran.
	//
	// +optional
	Replicas int32 `json:"replicas,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqb,categories=plainq
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Engine",type=string,JSONPath=`.status.engine`
// +kubebuilder:printcolumn:name="Size",type=string,JSONPath=`.status.compressedSize`
// +kubebuilder:printcolumn:name="Duration",type=string,JSONPath=`.status.duration`
// +kubebuilder:printcolumn:name="Verified",type=string,JSONPath=`.status.verification.result`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQBackup is one backup run and the record of how to read it back.
type PlainQBackup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQBackupSpec   `json:"spec,omitempty"`
	Status PlainQBackupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlainQBackupList contains a list of PlainQBackup.
type PlainQBackupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQBackup `json:"items"`
}
