package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// RestoreStrategy selects how a restore reaches its target.
//
// +kubebuilder:validation:Enum=NewInstance;InPlace
type RestoreStrategy string

const (
	// RestoreNewInstance restores into a fresh PlainQ, leaving the damaged
	// one untouched so the two can be compared and cut over deliberately.
	// The default, and the one to reach for at 3am.
	RestoreNewInstance RestoreStrategy = "NewInstance"

	// RestoreInPlace overwrites an existing instance's database. Requires
	// AllowDataLoss.
	RestoreInPlace RestoreStrategy = "InPlace"
)

// RestorePhase is the lifecycle of a restore.
//
// +kubebuilder:validation:Enum=Pending;Preparing;Restoring;Verifying;Completed;Failed
type RestorePhase string

const (
	RestorePending   RestorePhase = "Pending"
	RestorePreparing RestorePhase = "Preparing"
	RestoreRestoring RestorePhase = "Restoring"
	RestoreVerifying RestorePhase = "Verifying"
	RestoreCompleted RestorePhase = "Completed"
	RestoreFailed    RestorePhase = "Failed"
)

// PlainQRestoreSpec is the desired restore.
type PlainQRestoreSpec struct {
	// Source names what to restore from.
	Source RestoreSource `json:"source"`

	// Target names where to restore to.
	Target RestoreTarget `json:"target"`

	// AllowDataLoss is required for the InPlace strategy, which overwrites
	// a live database.
	//
	// +optional
	AllowDataLoss bool `json:"allowDataLoss,omitempty"`

	// RecreateResources re-applies the PlainQQueue and PlainQTopic objects
	// against the target once it is serving. A restored instance mints new
	// queue IDs, which is why references are by object name.
	//
	// +kubebuilder:default=true
	// +optional
	RecreateResources *bool `json:"recreateResources,omitempty"`
}

// RestoreSource names what to restore from. Exactly one of BackupRef,
// PolicyRef or Location must be set.
type RestoreSource struct {
	// BackupRef names a PlainQBackup. Its frozen effectiveConfig supplies
	// both how to read the artifact and the shape of the instance it came
	// from.
	//
	// +optional
	BackupRef *LocalObjectReference `json:"backupRef,omitempty"`

	// PolicyRef with PointInTime restores from continuous replication.
	//
	// +optional
	PolicyRef *LocalObjectReference `json:"policyRef,omitempty"`

	// PointInTime to recover to, used with PolicyRef.
	//
	// +optional
	PointInTime *metav1.Time `json:"pointInTime,omitempty"`

	// Location is a raw artifact URI the operator did not create — a file
	// copied in from another cluster, or one whose PlainQBackup has been
	// garbage collected.
	//
	// There is nothing to inherit a spec from in this case, so
	// Target.NewInstance.Spec must be complete. The webhook enforces it.
	//
	// +optional
	Location string `json:"location,omitempty"`

	// Destination holds the credentials needed to read Location.
	//
	// +optional
	Destination *Destination `json:"destination,omitempty"`

	// Compression of the raw artifact. It cannot be inferred reliably.
	//
	// +optional
	Compression Compression `json:"compression,omitempty"`

	// Encryption identity needed to decrypt the raw artifact.
	//
	// +optional
	Encryption *EncryptionSpec `json:"encryption,omitempty"`
}

// RestoreTarget names where to restore to.
type RestoreTarget struct {
	// Strategy selects the restore path.
	//
	// +kubebuilder:default=NewInstance
	// +optional
	Strategy RestoreStrategy `json:"strategy,omitempty"`

	// NewInstance describes the instance to create.
	//
	// +optional
	NewInstance *NewInstanceTarget `json:"newInstance,omitempty"`

	// InPlace names an existing instance to overwrite.
	//
	// +optional
	InPlace *InPlaceTarget `json:"inPlace,omitempty"`
}

// NewInstanceTarget describes the instance a restore creates.
type NewInstanceTarget struct {
	// Name of the new PlainQ.
	Name string `json:"name"`

	// Spec is an overlay on the inherited base. The base comes from the
	// backup's frozen effectiveConfig.source, or from the policy's target
	// instance. Raw-location sources have no base, so this must be complete
	// for them.
	//
	// +optional
	Spec *PlainQSpec `json:"spec,omitempty"`
}

// InPlaceTarget names an existing instance to overwrite.
type InPlaceTarget struct {
	// PlainQRef names the instance.
	PlainQRef LocalObjectReference `json:"plainqRef"`
}

// PlainQRestoreStatus is the observed state of a restore.
type PlainQRestoreStatus struct {
	// Phase of the restore.
	//
	// +optional
	Phase RestorePhase `json:"phase,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// RestoredTo names the instance now holding the data.
	//
	// +optional
	RestoredTo string `json:"restoredTo,omitempty"`

	// RestoredAt timestamp.
	//
	// +optional
	RestoredAt *metav1.Time `json:"restoredAt,omitempty"`

	// BytesRestored from the artifact.
	//
	// +optional
	BytesRestored string `json:"bytesRestored,omitempty"`

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

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqr,categories=plainq
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Strategy",type=string,JSONPath=`.spec.target.strategy`
// +kubebuilder:printcolumn:name="Restored To",type=string,JSONPath=`.status.restoredTo`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQRestore restores a backup into an existing or brand-new instance.
//
// The instance a restore creates is deliberately NOT owned by the restore
// object: it carries a plainq.dev/restored-from annotation and no controller
// owner reference. A restore record is an operation log that people clean up;
// the instance it produced is the thing they now run. Garbage collecting the
// former must never delete the latter.
type PlainQRestore struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQRestoreSpec   `json:"spec,omitempty"`
	Status PlainQRestoreStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlainQRestoreList contains a list of PlainQRestore.
type PlainQRestoreList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQRestore `json:"items"`
}
