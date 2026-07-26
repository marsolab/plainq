package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PlainQTopicSpec is the desired state of a topic and its fan-out.
type PlainQTopicSpec struct {
	// ServerRef points at the instance that holds the topic.
	ServerRef ServerReference `json:"serverRef"`

	// TopicName on the server. Defaults to metadata.name. Immutable.
	//
	// +optional
	TopicName string `json:"topicName,omitempty"`

	// Subscriptions are reconciled as a set: entries here are subscribed,
	// entries on the server but absent here are unsubscribed.
	//
	// +optional
	Subscriptions []TopicSubscription `json:"subscriptions,omitempty"`

	// DeletionPolicy decides whether deleting this object deletes the topic.
	//
	// +kubebuilder:default=Retain
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// TopicSubscription routes published messages into a queue. Exactly one of
// QueueRef or QueueID must be set.
type TopicSubscription struct {
	// QueueRef names a PlainQQueue in the same namespace.
	//
	// +optional
	QueueRef *LocalObjectReference `json:"queueRef,omitempty"`

	// QueueID names a queue the operator does not manage.
	//
	// +optional
	QueueID string `json:"queueID,omitempty"`
}

// PlainQTopicStatus is the observed state of a topic.
type PlainQTopicStatus struct {
	// TopicID assigned by the server.
	//
	// +optional
	TopicID string `json:"topicID,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Subscriptions currently established.
	//
	// +optional
	Subscriptions []SubscriptionStatus `json:"subscriptions,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// SubscriptionStatus is one established subscription.
type SubscriptionStatus struct {
	// Queue is the PlainQQueue object name, when the subscription came from
	// a reference rather than a raw ID.
	//
	// +optional
	Queue string `json:"queue,omitempty"`

	// QueueID on the server.
	//
	// +optional
	QueueID string `json:"queueID,omitempty"`

	// SubscriptionID assigned by the server.
	//
	// +optional
	SubscriptionID string `json:"subscriptionID,omitempty"`

	// Ready reports that the subscription is established.
	//
	// +optional
	Ready bool `json:"ready,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqt,categories=plainq
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Topic ID",type=string,JSONPath=`.status.topicID`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQTopic is a topic and its subscriptions on a PlainQ instance.
type PlainQTopic struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQTopicSpec   `json:"spec,omitempty"`
	Status PlainQTopicStatus `json:"status,omitempty"`
}

// ResolvedTopicName returns the topic name on the server.
func (t *PlainQTopic) ResolvedTopicName() string {
	if t.Spec.TopicName != "" {
		return t.Spec.TopicName
	}

	return t.Name
}

// +kubebuilder:object:root=true

// PlainQTopicList contains a list of PlainQTopic.
type PlainQTopicList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQTopic `json:"items"`
}
