package controller

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// apiutilGVK resolves an object's GroupVersionKind from the scheme.
//
// Typed server-side apply sends the kind on the wire, and a typed Go value
// carries no TypeMeta until something fills it in.
func apiutilGVK(scheme *runtime.Scheme, obj client.Object) (schema.GroupVersionKind, error) {
	gvks, _, err := scheme.ObjectKinds(obj)
	if err != nil {
		return schema.GroupVersionKind{}, fmt.Errorf("resolve kind for %T: %w", obj, err)
	}

	if len(gvks) == 0 {
		return schema.GroupVersionKind{}, fmt.Errorf("no kind registered for %T", obj)
	}

	return gvks[0], nil
}
