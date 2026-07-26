package controller

import (
	"context"
	"fmt"

	"github.com/marsolab/plainq/operator/internal/render"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// fieldOwner identifies the operator as the manager of the fields it sets.
//
// Server-side apply with a stable owner is what makes hand-edits to owned
// objects revert deliberately rather than turn into a tug of war between a
// human and a controller. It is also why a cutover cannot be performed by
// editing an instance's Service: the next reconcile would take it back. The
// alias Service exists for exactly that reason.
const fieldOwner = client.FieldOwner(render.ManagedBy)

// applier applies rendered objects with server-side apply.
type applier struct {
	client client.Client
	scheme *runtime.Scheme
}

// apply sets the owner reference and applies the object. Passing owner as nil
// applies it unowned, which is deliberate for objects that must outlive the
// resource that created them.
func (a applier) apply(ctx context.Context, obj client.Object, owner client.Object) error {
	if owner != nil {
		if err := controllerutil.SetControllerReference(owner, obj, a.scheme); err != nil {
			return fmt.Errorf("set owner reference on %s: %w", describe(obj), err)
		}
	}

	// Typed server-side apply needs the GroupVersionKind on the wire.
	gvk, err := apiutilGVK(a.scheme, obj)
	if err != nil {
		return err
	}

	obj.GetObjectKind().SetGroupVersionKind(gvk)

	if err := a.client.Patch(ctx, obj, client.Apply, fieldOwner, client.ForceOwnership); err != nil {
		return fmt.Errorf("apply %s: %w", describe(obj), err)
	}

	return nil
}

func describe(obj client.Object) string {
	return fmt.Sprintf("%T %s/%s", obj, obj.GetNamespace(), obj.GetName())
}
