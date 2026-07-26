// Package v1alpha1 contains the API schema definitions for the plainq.dev
// API group.
//
// +kubebuilder:object:generate=true
// +groupName=plainq.dev
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	// GroupVersion is the group and version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "plainq.dev", Version: "v1alpha1"}

	// SchemeBuilder registers the Go types with a scheme.
	//
	// This uses apimachinery's builder rather than controller-runtime's, so
	// the API package stays importable by clients that do not want the
	// controller machinery in their dependency graph — which is the whole
	// reason controller-runtime deprecated its own helper.
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

	// AddToScheme adds the types in this group-version to a scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

// addKnownTypes registers every kind in this group.
func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&PlainQ{}, &PlainQList{},
		&PlainQQueue{}, &PlainQQueueList{},
		&PlainQTopic{}, &PlainQTopicList{},
		&PlainQAccount{}, &PlainQAccountList{},
		&PlainQBackupPolicy{}, &PlainQBackupPolicyList{},
		&PlainQBackup{}, &PlainQBackupList{},
		&PlainQRestore{}, &PlainQRestoreList{},
	)

	metav1.AddToGroupVersion(scheme, GroupVersion)

	return nil
}
