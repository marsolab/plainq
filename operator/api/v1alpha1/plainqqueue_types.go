package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// EvictionPolicy decides what happens to a message that exhausts its retry
// budget or its retention period.
//
// +kubebuilder:validation:Enum=Drop;DeadLetter;Reorder
type EvictionPolicy string

const (
	// EvictionDrop removes the message permanently.
	EvictionDrop EvictionPolicy = "Drop"

	// EvictionDeadLetter moves the message to another queue.
	EvictionDeadLetter EvictionPolicy = "DeadLetter"

	// EvictionReorder reinserts the message at the back of the queue.
	EvictionReorder EvictionPolicy = "Reorder"
)

// UpdatePolicy decides what the operator does when a queue's settings drift
// from spec.
//
// Queue settings are create-only on the server: there is no UpdateQueue RPC
// and no PUT route. The operator does not pretend otherwise.
//
// +kubebuilder:validation:Enum=Reject;Recreate
type UpdatePolicy string

const (
	// UpdateReject reports the drift as a condition and leaves the queue
	// serving with its original settings. Nothing is destroyed to satisfy a
	// YAML edit. This is the default.
	UpdateReject UpdatePolicy = "Reject"

	// UpdateRecreate deletes and recreates the queue. Every message in it is
	// gone, so it requires AllowDataLoss.
	UpdateRecreate UpdatePolicy = "Recreate"
)

// PlainQQueueSpec is the desired state of a queue.
type PlainQQueueSpec struct {
	// ServerRef points at the instance that holds the queue.
	ServerRef ServerReference `json:"serverRef"`

	// QueueName on the server. Defaults to metadata.name. Immutable: the
	// server has no rename, so changing it would mean creating a second
	// queue and abandoning the first.
	//
	// +optional
	QueueName string `json:"queueName,omitempty"`

	// RetentionPeriod after which messages expire.
	//
	// +optional
	RetentionPeriod string `json:"retentionPeriod,omitempty"`

	// VisibilityTimeout is how long a received message stays invisible.
	//
	// +optional
	VisibilityTimeout string `json:"visibilityTimeout,omitempty"`

	// MaxReceiveAttempts is the retry budget before eviction.
	//
	// +kubebuilder:validation:Minimum=0
	// +optional
	MaxReceiveAttempts uint32 `json:"maxReceiveAttempts,omitempty"`

	// EvictionPolicy applied when a budget is exhausted.
	//
	// +kubebuilder:default=Drop
	// +optional
	EvictionPolicy EvictionPolicy `json:"evictionPolicy,omitempty"`

	// DeadLetterQueueRef names another PlainQQueue to receive evicted
	// messages. The operator resolves it to an ID and waits for that queue
	// to exist, so apply order does not matter.
	//
	// +optional
	DeadLetterQueueRef *LocalObjectReference `json:"deadLetterQueueRef,omitempty"`

	// DeadLetterQueueID names a queue by server-assigned ID, for a queue the
	// operator does not manage.
	//
	// +optional
	DeadLetterQueueID string `json:"deadLetterQueueID,omitempty"`

	// UpdatePolicy decides what happens when settings drift.
	//
	// +kubebuilder:default=Reject
	// +optional
	UpdatePolicy UpdatePolicy `json:"updatePolicy,omitempty"`

	// DeletionPolicy decides whether deleting this object deletes the queue.
	//
	// +kubebuilder:default=Retain
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// AllowDataLoss gates the destructive paths: recreating a queue, and
	// deleting one that still holds messages.
	//
	// +optional
	AllowDataLoss bool `json:"allowDataLoss,omitempty"`
}

// PlainQQueueStatus is the observed state of a queue.
type PlainQQueueStatus struct {
	// QueueID assigned by the server. Cached so name resolution happens once
	// per queue rather than once per reconcile.
	//
	// +optional
	QueueID string `json:"queueID,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// DriftedFields names settings that differ from spec and cannot be
	// changed in place.
	//
	// +optional
	DriftedFields []string `json:"driftedFields,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqq,categories=plainq
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Queue ID",type=string,JSONPath=`.status.queueID`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQQueue is a queue on a PlainQ instance.
type PlainQQueue struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQQueueSpec   `json:"spec,omitempty"`
	Status PlainQQueueStatus `json:"status,omitempty"`
}

// ResolvedQueueName returns the queue name on the server: the explicit spec
// value when set, otherwise the object name.
func (q *PlainQQueue) ResolvedQueueName() string {
	if q.Spec.QueueName != "" {
		return q.Spec.QueueName
	}

	return q.Name
}

// +kubebuilder:object:root=true

// PlainQQueueList contains a list of PlainQQueue.
type PlainQQueueList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQQueue `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PlainQQueue{}, &PlainQQueueList{})
}
