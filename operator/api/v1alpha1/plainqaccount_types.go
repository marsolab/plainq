package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PlainQAccountSpec is the desired state of an account.
type PlainQAccountSpec struct {
	// ServerRef points at the instance that holds the account.
	ServerRef ServerReference `json:"serverRef"`

	// Email identifying the account.
	//
	// +kubebuilder:validation:MinLength=3
	Email string `json:"email"`

	// CredentialsSecretRef holds the password. The operator generates one
	// into this Secret when it does not exist, so a password never has to
	// appear in a manifest.
	//
	// +optional
	CredentialsSecretRef *CredentialsSecretReference `json:"credentialsSecretRef,omitempty"`

	// Role granted to the account.
	//
	// +kubebuilder:default=user
	// +optional
	Role string `json:"role,omitempty"`

	// Bootstrap creates this account through the onboarding endpoint, which
	// only works for the very first admin and self-closes afterwards.
	//
	// A non-bootstrap account goes through /api/v1/account/signup instead,
	// and that route refuses whenever the target instance has
	// auth.registration disabled — an admin token does not exempt it. The
	// validating webhook rejects that combination rather than letting the
	// reconciler discover it as a 401.
	//
	// +optional
	Bootstrap bool `json:"bootstrap,omitempty"`

	// DeletionPolicy decides whether deleting this object deletes the
	// account.
	//
	// +kubebuilder:default=Retain
	// +optional
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

// PlainQAccountStatus is the observed state of an account.
type PlainQAccountStatus struct {
	// AccountID assigned by the server.
	//
	// +optional
	AccountID string `json:"accountID,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pqa,categories=plainq
// +kubebuilder:printcolumn:name="Server",type=string,JSONPath=`.spec.serverRef.name`
// +kubebuilder:printcolumn:name="Email",type=string,JSONPath=`.spec.email`
// +kubebuilder:printcolumn:name="Role",type=string,JSONPath=`.spec.role`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQAccount is an account on a PlainQ instance, including the bootstrap
// admin that would otherwise require a browser.
type PlainQAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQAccountSpec   `json:"spec,omitempty"`
	Status PlainQAccountStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlainQAccountList contains a list of PlainQAccount.
type PlainQAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PlainQAccount{}, &PlainQAccountList{})
}
