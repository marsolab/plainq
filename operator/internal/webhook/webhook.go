// Package webhook wires the admission rules in internal/validation into
// controller-runtime.
//
// The rules themselves are pure functions there; this package only adapts
// them and resolves the live state a few of them need.
package webhook

import (
	"context"
	"fmt"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/validation"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlbuilder "sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// SetupAll registers every webhook with the manager.
func SetupAll(mgr ctrl.Manager) error {
	kube := mgr.GetClient()

	setups := []func() error{
		func() error {
			return setupWithDefaulter(mgr, &plainqv1alpha1.PlainQ{}, &PlainQWebhook{Client: kube})
		},
		func() error { return setup(mgr, &plainqv1alpha1.PlainQQueue{}, &QueueWebhook{}) },
		func() error { return setup(mgr, &plainqv1alpha1.PlainQTopic{}, &TopicWebhook{}) },
		func() error { return setup(mgr, &plainqv1alpha1.PlainQAccount{}, &AccountWebhook{Client: kube}) },
		func() error {
			return setup(mgr, &plainqv1alpha1.PlainQBackupPolicy{}, &BackupPolicyWebhook{Client: kube})
		},
		func() error { return setup(mgr, &plainqv1alpha1.PlainQRestore{}, &RestoreWebhook{}) },
	}

	for _, s := range setups {
		if err := s(); err != nil {
			return err
		}
	}

	return nil
}

// setup registers a validating webhook for one kind.
func setup[T runtime.Object](mgr ctrl.Manager, obj T, validator admission.Validator[T]) error {
	if err := ctrlbuilder.WebhookManagedBy(mgr, obj).WithValidator(validator).Complete(); err != nil {
		return fmt.Errorf("register webhook for %T: %w", obj, err)
	}

	return nil
}

// setupWithDefaulter registers both a mutating and a validating webhook.
func setupWithDefaulter[T runtime.Object](
	mgr ctrl.Manager,
	obj T,
	handler interface {
		admission.Validator[T]
		admission.Defaulter[T]
	},
) error {
	err := ctrlbuilder.WebhookManagedBy(mgr, obj).
		WithValidator(handler).
		WithDefaulter(handler).
		Complete()
	if err != nil {
		return fmt.Errorf("register webhook for %T: %w", obj, err)
	}

	return nil
}

// +kubebuilder:webhook:path=/mutate-plainq-dev-v1alpha1-plainq,mutating=true,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqs,verbs=create;update,versions=v1alpha1,name=mplainq.plainq.dev,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainq,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqs,verbs=create;update,versions=v1alpha1,name=vplainq.plainq.dev,admissionReviewVersions=v1

// PlainQWebhook defaults and validates PlainQ objects.
type PlainQWebhook struct {
	Client client.Client
}

var (
	_ admission.Defaulter[*plainqv1alpha1.PlainQ] = &PlainQWebhook{}
	_ admission.Validator[*plainqv1alpha1.PlainQ] = &PlainQWebhook{}
)

// Default fills empty fields.
func (w *PlainQWebhook) Default(_ context.Context, pq *plainqv1alpha1.PlainQ) error {
	pq.Spec.ApplyDefaults()

	return nil
}

// ValidateCreate checks a new instance.
func (w *PlainQWebhook) ValidateCreate(
	ctx context.Context,
	pq *plainqv1alpha1.PlainQ,
) (admission.Warnings, error) {
	errs := validation.ValidatePlainQ(pq)

	if err := w.validateAlias(ctx, pq); err != nil {
		errs = append(errs, err)
	}

	return warnings(pq), invalid(pq, "PlainQ", errs)
}

// ValidateUpdate additionally checks immutability and quorum.
func (w *PlainQWebhook) ValidateUpdate(
	ctx context.Context,
	old, updated *plainqv1alpha1.PlainQ,
) (admission.Warnings, error) {
	errs := validation.ValidatePlainQUpdate(old, updated)

	if err := w.validateAlias(ctx, updated); err != nil {
		errs = append(errs, err)
	}

	// Only the shape of a scale-in is checked here: whether each step can
	// commit depends on live membership, which the reconciler re-checks per
	// step as it drains.
	if updated.Spec.Cluster.Enabled && updated.Spec.Cluster.Replicas < 1 {
		errs = append(errs, field.Invalid(
			field.NewPath("spec", "cluster", "replicas"), updated.Spec.Cluster.Replicas,
			"a cluster cannot scale below one node"))
	}

	return warnings(updated), invalid(updated, "PlainQ", errs)
}

// ValidateDelete allows deletion.
func (w *PlainQWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQ,
) (admission.Warnings, error) {
	return nil, nil
}

func (w *PlainQWebhook) validateAlias(ctx context.Context, pq *plainqv1alpha1.PlainQ) *field.Error {
	alias := pq.Spec.Networking.Alias.Name
	if alias == "" || w.Client == nil {
		return nil
	}

	var siblings plainqv1alpha1.PlainQList

	// A failure to list is not a reason to refuse the write: admission
	// should not become a second availability dependency. The reconciler
	// re-checks the claim and reports a conflict as a condition.
	//nolint:nilerr // Deliberate: an unreadable cache must not block admission.
	if err := w.Client.List(ctx, &siblings, client.InNamespace(pq.Namespace)); err != nil {
		return nil
	}

	for i := range siblings.Items {
		other := &siblings.Items[i]
		if other.Name != pq.Name && other.Spec.Networking.Alias.Name == alias {
			return validation.ValidateAliasClaim(alias, pq.Name, other.Name)
		}
	}

	return nil
}

// warnings returns advisory notes that do not block admission.
func warnings(pq *plainqv1alpha1.PlainQ) admission.Warnings {
	var w admission.Warnings

	// An even cluster is legal — it happens mid-transition — but it buys
	// nothing: 2N tolerates the same N-1 failures as 2N-1.
	if pq.Spec.Cluster.Enabled && pq.Spec.Cluster.Replicas%2 == 0 {
		w = append(w, fmt.Sprintf(
			"a cluster of %d tolerates the same number of failures as one of %d; "+
				"an even node count costs a node and buys nothing",
			pq.Spec.Cluster.Replicas, pq.Spec.Cluster.Replicas-1))
	}

	if pq.Spec.Storage.Driver == plainqv1alpha1.StorageSQLite &&
		!plainqv1alpha1.BoolValue(pq.Spec.Storage.SQLite.Persistence.Enabled, true) {
		w = append(w, "persistence is disabled: the queue will not survive a pod restart")
	}

	if !plainqv1alpha1.BoolValue(pq.Spec.Auth.Enabled, true) &&
		!pq.Spec.Networking.NetworkPolicy.Enabled {
		w = append(w, "auth is disabled and no NetworkPolicy is configured: "+
			"both listeners are reachable by anything in the cluster")
	}

	return w
}

// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainqqueue,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqqueues,verbs=create;update,versions=v1alpha1,name=vplainqqueue.plainq.dev,admissionReviewVersions=v1

// QueueWebhook validates queues.
type QueueWebhook struct{}

var _ admission.Validator[*plainqv1alpha1.PlainQQueue] = &QueueWebhook{}

// ValidateCreate checks a new queue.
func (w *QueueWebhook) ValidateCreate(
	_ context.Context,
	queue *plainqv1alpha1.PlainQQueue,
) (admission.Warnings, error) {
	return nil, invalid(queue, "PlainQQueue", validation.ValidatePlainQQueue(queue))
}

// ValidateUpdate additionally rejects a rename.
func (w *QueueWebhook) ValidateUpdate(
	_ context.Context,
	old, updated *plainqv1alpha1.PlainQQueue,
) (admission.Warnings, error) {
	return nil, invalid(updated, "PlainQQueue", validation.ValidatePlainQQueueUpdate(old, updated))
}

// ValidateDelete allows deletion.
func (w *QueueWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQQueue,
) (admission.Warnings, error) {
	return nil, nil
}

// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainqtopic,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqtopics,verbs=create;update,versions=v1alpha1,name=vplainqtopic.plainq.dev,admissionReviewVersions=v1

// TopicWebhook validates topics.
type TopicWebhook struct{}

var _ admission.Validator[*plainqv1alpha1.PlainQTopic] = &TopicWebhook{}

// ValidateCreate checks a new topic.
func (w *TopicWebhook) ValidateCreate(
	_ context.Context,
	topic *plainqv1alpha1.PlainQTopic,
) (admission.Warnings, error) {
	return nil, invalid(topic, "PlainQTopic", validation.ValidatePlainQTopic(topic))
}

// ValidateUpdate checks an updated topic.
func (w *TopicWebhook) ValidateUpdate(
	ctx context.Context,
	_, updated *plainqv1alpha1.PlainQTopic,
) (admission.Warnings, error) {
	return w.ValidateCreate(ctx, updated)
}

// ValidateDelete allows deletion.
func (w *TopicWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQTopic,
) (admission.Warnings, error) {
	return nil, nil
}

// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainqaccount,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqaccounts,verbs=create;update,versions=v1alpha1,name=vplainqaccount.plainq.dev,admissionReviewVersions=v1

// AccountWebhook validates accounts against the instance they target.
type AccountWebhook struct {
	Client client.Client
}

var _ admission.Validator[*plainqv1alpha1.PlainQAccount] = &AccountWebhook{}

// ValidateCreate checks a new account.
//
// The interesting rule needs the target instance: a non-bootstrap account can
// only be created while self-registration is enabled, because signup is the
// only creation route the server has.
func (w *AccountWebhook) ValidateCreate(
	ctx context.Context,
	account *plainqv1alpha1.PlainQAccount,
) (admission.Warnings, error) {
	// Default to permitting when the target cannot be inspected — an
	// external endpoint, or an instance not created yet. The reconciler
	// reports the refusal in that case.
	registration := true

	if name := account.Spec.ServerRef.Name; name != "" && w.Client != nil {
		var pq plainqv1alpha1.PlainQ

		key := client.ObjectKey{Namespace: account.Namespace, Name: name}
		if err := w.Client.Get(ctx, key, &pq); err == nil {
			registration = plainqv1alpha1.BoolValue(pq.Spec.Auth.Registration, true)
		}
	}

	return nil, invalid(account, "PlainQAccount",
		validation.ValidatePlainQAccount(account, registration))
}

// ValidateUpdate checks an updated account.
func (w *AccountWebhook) ValidateUpdate(
	ctx context.Context,
	_, updated *plainqv1alpha1.PlainQAccount,
) (admission.Warnings, error) {
	return w.ValidateCreate(ctx, updated)
}

// ValidateDelete allows deletion.
func (w *AccountWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQAccount,
) (admission.Warnings, error) {
	return nil, nil
}

// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainqbackuppolicy,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqbackuppolicies,verbs=create;update,versions=v1alpha1,name=vplainqbackuppolicy.plainq.dev,admissionReviewVersions=v1

// BackupPolicyWebhook validates backup regimes.
type BackupPolicyWebhook struct {
	Client client.Client
}

var _ admission.Validator[*plainqv1alpha1.PlainQBackupPolicy] = &BackupPolicyWebhook{}

// ValidateCreate checks a new policy against the target's storage driver.
func (w *BackupPolicyWebhook) ValidateCreate(
	ctx context.Context,
	policy *plainqv1alpha1.PlainQBackupPolicy,
) (admission.Warnings, error) {
	var driver plainqv1alpha1.StorageDriver

	if name := policy.Spec.ServerRef.Name; name != "" && w.Client != nil {
		var pq plainqv1alpha1.PlainQ

		key := client.ObjectKey{Namespace: policy.Namespace, Name: name}
		if err := w.Client.Get(ctx, key, &pq); err == nil {
			driver = pq.Spec.Storage.Driver
		}
	}

	return nil, invalid(policy, "PlainQBackupPolicy",
		validation.ValidatePlainQBackupPolicy(policy, driver))
}

// ValidateUpdate checks an updated policy.
func (w *BackupPolicyWebhook) ValidateUpdate(
	ctx context.Context,
	_, updated *plainqv1alpha1.PlainQBackupPolicy,
) (admission.Warnings, error) {
	return w.ValidateCreate(ctx, updated)
}

// ValidateDelete allows deletion.
func (w *BackupPolicyWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQBackupPolicy,
) (admission.Warnings, error) {
	return nil, nil
}

// +kubebuilder:webhook:path=/validate-plainq-dev-v1alpha1-plainqrestore,mutating=false,failurePolicy=fail,sideEffects=None,groups=plainq.dev,resources=plainqrestores,verbs=create;update,versions=v1alpha1,name=vplainqrestore.plainq.dev,admissionReviewVersions=v1

// RestoreWebhook validates restores.
type RestoreWebhook struct{}

var _ admission.Validator[*plainqv1alpha1.PlainQRestore] = &RestoreWebhook{}

// ValidateCreate checks a new restore.
func (w *RestoreWebhook) ValidateCreate(
	_ context.Context,
	restore *plainqv1alpha1.PlainQRestore,
) (admission.Warnings, error) {
	return nil, invalid(restore, "PlainQRestore", validation.ValidatePlainQRestore(restore))
}

// ValidateUpdate checks an updated restore.
func (w *RestoreWebhook) ValidateUpdate(
	ctx context.Context,
	_, updated *plainqv1alpha1.PlainQRestore,
) (admission.Warnings, error) {
	return w.ValidateCreate(ctx, updated)
}

// ValidateDelete allows deletion.
func (w *RestoreWebhook) ValidateDelete(
	_ context.Context,
	_ *plainqv1alpha1.PlainQRestore,
) (admission.Warnings, error) {
	return nil, nil
}

// invalid turns a field error list into an admission rejection.
//
// The kind is passed explicitly: a typed object carries no TypeMeta when it
// arrives through the generic decoder, so reading it back off the object
// would produce an empty kind in the message.
func invalid(obj client.Object, kind string, errs field.ErrorList) error {
	if len(errs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		schema.GroupKind{Group: plainqv1alpha1.GroupVersion.Group, Kind: kind},
		obj.GetName(), errs)
}
