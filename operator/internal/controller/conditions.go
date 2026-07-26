package controller

import (
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// maxConditionMessage bounds a condition message. The API server rejects
// anything longer, and an error from a dependency can be arbitrarily long.
const maxConditionMessage = 32768

// setCondition records a condition, leaving LastTransitionTime alone when
// only the message changed.
func setCondition(
	conditions *[]metav1.Condition,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
	generation int64,
) {
	if len(message) > maxConditionMessage {
		message = message[:maxConditionMessage]
	}

	if reason == "" {
		reason = "Unknown"
	}

	meta.SetStatusCondition(conditions, metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation,
	})
}

func boolCondition(v bool) metav1.ConditionStatus {
	if v {
		return metav1.ConditionTrue
	}

	return metav1.ConditionFalse
}

// Thin wrappers over controllerutil, so call sites read consistently and the
// dependency stays in one place.

func controllerutilContainsFinalizer(obj client.Object, finalizer string) bool {
	return controllerutil.ContainsFinalizer(obj, finalizer)
}

func controllerutilAddFinalizer(obj client.Object, finalizer string) {
	controllerutil.AddFinalizer(obj, finalizer)
}

func controllerutilRemoveFinalizer(obj client.Object, finalizer string) {
	controllerutil.RemoveFinalizer(obj, finalizer)
}

func controllerutilSetOwner(owner, owned client.Object, scheme *runtime.Scheme) error {
	//nolint:wrapcheck // The caller adds context; this is a one-line shim.
	return controllerutil.SetControllerReference(owner, owned, scheme)
}
