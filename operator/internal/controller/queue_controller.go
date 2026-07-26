package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/plainqapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// queueFinalizer honors the deletion policy before the object disappears.
const queueFinalizer = "plainq.dev/queue-finalizer"

// PlainQQueueReconciler keeps queues on a server matching their objects.
type PlainQQueueReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Clients  *ClientFactory
}

// +kubebuilder:rbac:groups=plainq.dev,resources=plainqqueues,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqqueues/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqqueues/finalizers,verbs=update

// Reconcile creates the queue, or reports why it cannot.
func (r *PlainQQueueReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var queue plainqv1alpha1.PlainQQueue
	if err := r.Get(ctx, req.NamespacedName, &queue); err != nil {
		return ctrl.Result{}, fmt.Errorf("get PlainQQueue: %w", client.IgnoreNotFound(err))
	}

	api, err := r.Clients.For(ctx, queue.Namespace, queue.Spec.ServerRef)
	if err != nil {
		if !queue.DeletionTimestamp.IsZero() {
			// The instance is gone. Nothing can be deleted server-side, and
			// blocking deletion on an unreachable server would strand the
			// object forever.
			return r.dropFinalizer(ctx, &queue)
		}

		return r.reportWaiting(ctx, &queue, err)
	}

	if !queue.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &queue, api)
	}

	if !controllerutilContainsFinalizer(&queue, queueFinalizer) {
		controllerutilAddFinalizer(&queue, queueFinalizer)

		if err := r.Update(ctx, &queue); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	deadLetterID, err := r.resolveDeadLetter(ctx, &queue)
	if err != nil {
		return r.reportWaiting(ctx, &queue, err)
	}

	existing, err := r.find(ctx, &queue, api)
	if err != nil {
		return r.reportWaiting(ctx, &queue, err)
	}

	if existing == nil {
		return r.create(ctx, &queue, api, deadLetterID)
	}

	return r.reconcileDrift(ctx, &queue, api, existing, deadLetterID)
}

// find locates the queue, preferring the cached ID so the name scan happens
// once per queue rather than once per reconcile.
func (r *PlainQQueueReconciler) find(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	api *plainqapi.Client,
) (*plainqapi.Queue, error) {
	if id := queue.Status.QueueID; id != "" {
		found, err := api.DescribeQueue(ctx, id)
		if err == nil {
			return found, nil
		}

		if !errors.Is(err, plainqapi.ErrNotFound) {
			return nil, fmt.Errorf("describe queue: %w", err)
		}
		// The cached ID is stale — the instance was restored, or the queue
		// was deleted out of band. Fall through to a name lookup.
	}

	found, err := api.ResolveQueueByName(ctx, queue.ResolvedQueueName())
	if errors.Is(err, plainqapi.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("resolve queue by name: %w", err)
	}

	return found, nil
}

func (r *PlainQQueueReconciler) create(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	api *plainqapi.Client,
	deadLetterID string,
) (ctrl.Result, error) {
	req, err := createRequest(queue, deadLetterID)
	if err != nil {
		return r.reportWaiting(ctx, queue, err)
	}

	id, err := api.CreateQueue(ctx, req)
	if err != nil {
		return r.reportWaiting(ctx, queue, err)
	}

	r.Recorder.Eventf(queue, corev1.EventTypeNormal, "QueueCreated",
		"created queue %q as %s", queue.ResolvedQueueName(), id)

	queue.Status.QueueID = id
	queue.Status.DriftedFields = nil

	return r.reportReady(ctx, queue, true, "")
}

// reconcileDrift compares server settings against spec.
//
// Queue settings are create-only: there is no UpdateQueue RPC and no PUT
// route. So drift is either reported and left alone, or resolved by
// destroying and recreating the queue — which is only allowed with an
// explicit opt-in, because it discards every message in it.
func (r *PlainQQueueReconciler) reconcileDrift(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	api *plainqapi.Client,
	existing *plainqapi.Queue,
	deadLetterID string,
) (ctrl.Result, error) {
	queue.Status.QueueID = existing.QueueID

	drift := driftedFields(queue, existing, deadLetterID)
	if len(drift) == 0 {
		queue.Status.DriftedFields = nil

		return r.reportReady(ctx, queue, true, "")
	}

	queue.Status.DriftedFields = drift

	if queue.Spec.UpdatePolicy != plainqv1alpha1.UpdateRecreate || !queue.Spec.AllowDataLoss {
		message := fmt.Sprintf(
			"the server cannot change %s after creation and there is no UpdateQueue API; "+
				"the queue keeps serving with its original settings",
			strings.Join(drift, ", "))

		r.Recorder.Event(queue, corev1.EventTypeWarning,
			plainqv1alpha1.ReasonImmutableFieldChanged, message)

		return r.reportReady(ctx, queue, false, message)
	}

	// Recreate: explicitly requested, explicitly acknowledged as lossy.
	if err := api.DeleteQueue(ctx, existing.QueueID); err != nil {
		return r.reportWaiting(ctx, queue, err)
	}

	r.Recorder.Eventf(queue, corev1.EventTypeWarning, "QueueRecreated",
		"deleted and recreated queue %q to apply %s; every message in it was discarded",
		queue.ResolvedQueueName(), strings.Join(drift, ", "))

	return r.create(ctx, queue, api, deadLetterID)
}

// driftedFields names the settings that differ. Zero values in spec mean
// "unset", which the server fills with its own defaults, so they are not
// drift.
//
//nolint:cyclop // One comparison per queue setting.
func driftedFields(queue *plainqv1alpha1.PlainQQueue, existing *plainqapi.Queue, deadLetterID string) []string {
	var drift []string

	if want, err := seconds(queue.Spec.RetentionPeriod); err == nil && want > 0 &&
		want != existing.RetentionPeriodSeconds {
		drift = append(drift, "retentionPeriod")
	}

	if want, err := seconds(queue.Spec.VisibilityTimeout); err == nil && want > 0 &&
		want != existing.VisibilityTimeoutSeconds {
		drift = append(drift, "visibilityTimeout")
	}

	if want := queue.Spec.MaxReceiveAttempts; want > 0 && want != existing.MaxReceiveAttempts {
		drift = append(drift, "maxReceiveAttempts")
	}

	if want := wireEvictionPolicy(queue.Spec.EvictionPolicy); want != "" &&
		existing.EvictionPolicy != "" && want != existing.EvictionPolicy {
		drift = append(drift, "evictionPolicy")
	}

	if deadLetterID != "" && deadLetterID != existing.DeadLetterQueueID {
		drift = append(drift, "deadLetterQueue")
	}

	return drift
}

// resolveDeadLetter turns a dead-letter reference into a server-assigned ID,
// waiting for the referenced queue to exist.
//
// This is what makes apply order irrelevant: a queue naming a dead-letter
// queue declared later in the same directory converges on a later pass rather
// than failing.
func (r *PlainQQueueReconciler) resolveDeadLetter(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
) (string, error) {
	if id := queue.Spec.DeadLetterQueueID; id != "" {
		return id, nil
	}

	ref := queue.Spec.DeadLetterQueueRef
	if ref == nil {
		return "", nil
	}

	var target plainqv1alpha1.PlainQQueue

	key := client.ObjectKey{Namespace: queue.Namespace, Name: ref.Name}
	if err := r.Get(ctx, key, &target); err != nil {
		return "", fmt.Errorf("dead-letter queue %q: %w", ref.Name, err)
	}

	if target.Status.QueueID == "" {
		return "", fmt.Errorf("%w: dead-letter queue %q has no id yet", errServerNotReady, ref.Name)
	}

	return target.Status.QueueID, nil
}

func (r *PlainQQueueReconciler) finalize(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	api *plainqapi.Client,
) (ctrl.Result, error) {
	if !controllerutilContainsFinalizer(queue, queueFinalizer) {
		return ctrl.Result{}, nil
	}

	// Retain is the default because deleting a Kubernetes object should not
	// silently destroy data on a server that outlives it.
	if queue.Spec.DeletionPolicy != plainqv1alpha1.DeletionDelete || queue.Status.QueueID == "" {
		return r.dropFinalizer(ctx, queue)
	}

	if !queue.Spec.AllowDataLoss {
		count, err := api.QueueMessageCount(ctx, queue.Status.QueueID)
		if err == nil && count > 0 {
			message := "refusing to delete a queue that still holds messages; " +
				"set allowDataLoss=true or drain it first"

			r.Recorder.Event(queue, corev1.EventTypeWarning, "DeletionBlocked", message)
			setCondition(&queue.Status.Conditions, plainqv1alpha1.ConditionReady,
				metav1.ConditionFalse, "DeletionBlocked", message, queue.Generation)

			if err := r.Status().Update(ctx, queue); err != nil {
				return ctrl.Result{}, fmt.Errorf("update status: %w", err)
			}

			return ctrl.Result{RequeueAfter: time.Minute}, nil
		}
	}

	if err := api.DeleteQueue(ctx, queue.Status.QueueID); err != nil {
		return ctrl.Result{}, fmt.Errorf("delete queue: %w", err)
	}

	r.Recorder.Eventf(queue, corev1.EventTypeNormal, "QueueDeleted",
		"deleted queue %q", queue.ResolvedQueueName())

	return r.dropFinalizer(ctx, queue)
}

func (r *PlainQQueueReconciler) dropFinalizer(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
) (ctrl.Result, error) {
	if !controllerutilContainsFinalizer(queue, queueFinalizer) {
		return ctrl.Result{}, nil
	}

	controllerutilRemoveFinalizer(queue, queueFinalizer)

	if err := r.Update(ctx, queue); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *PlainQQueueReconciler) reportReady(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	synced bool,
	driftMessage string,
) (ctrl.Result, error) {
	queue.Status.ObservedGeneration = queue.Generation

	setCondition(&queue.Status.Conditions, plainqv1alpha1.ConditionReady,
		metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable, "the queue exists", queue.Generation)

	if synced {
		setCondition(&queue.Status.Conditions, plainqv1alpha1.ConditionSynced,
			metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable,
			"settings match spec", queue.Generation)
	} else {
		setCondition(&queue.Status.Conditions, plainqv1alpha1.ConditionSynced,
			metav1.ConditionFalse, plainqv1alpha1.ReasonImmutableFieldChanged,
			driftMessage, queue.Generation)
	}

	if err := r.Status().Update(ctx, queue); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueSteady}, nil
}

func (r *PlainQQueueReconciler) reportWaiting(
	ctx context.Context,
	queue *plainqv1alpha1.PlainQQueue,
	cause error,
) (ctrl.Result, error) {
	reason := plainqv1alpha1.ReasonServerUnreachable
	if errors.Is(cause, errServerNotReady) {
		reason = plainqv1alpha1.ReasonWaitingForDependency
	}

	setCondition(&queue.Status.Conditions, plainqv1alpha1.ConditionReady,
		metav1.ConditionFalse, reason, cause.Error(), queue.Generation)

	if err := r.Status().Update(ctx, queue); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueBackoff}, nil
}

// SetupWithManager registers the reconciler.
func (r *PlainQQueueReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&plainqv1alpha1.PlainQQueue{}).
		Named("plainqqueue").
		Complete(r)
	if err != nil {
		return fmt.Errorf("build queue controller: %w", err)
	}

	return nil
}

func createRequest(
	queue *plainqv1alpha1.PlainQQueue,
	deadLetterID string,
) (plainqapi.CreateQueueRequest, error) {
	retention, err := seconds(queue.Spec.RetentionPeriod)
	if err != nil {
		return plainqapi.CreateQueueRequest{}, fmt.Errorf("retentionPeriod: %w", err)
	}

	visibility, err := seconds(queue.Spec.VisibilityTimeout)
	if err != nil {
		return plainqapi.CreateQueueRequest{}, fmt.Errorf("visibilityTimeout: %w", err)
	}

	return plainqapi.CreateQueueRequest{
		QueueName:                queue.ResolvedQueueName(),
		RetentionPeriodSeconds:   retention,
		VisibilityTimeoutSeconds: visibility,
		MaxReceiveAttempts:       queue.Spec.MaxReceiveAttempts,
		EvictionPolicy:           wireEvictionPolicy(queue.Spec.EvictionPolicy),
		DeadLetterQueueID:        deadLetterID,
	}, nil
}

// seconds parses a Go duration string into whole seconds, which is the unit
// the wire protocol uses.
func seconds(value string) (uint64, error) {
	if value == "" {
		return 0, nil
	}

	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse duration %q: %w", value, err)
	}

	if d < 0 {
		return 0, fmt.Errorf("duration %q is negative", value)
	}

	return uint64(d.Seconds()), nil
}

func wireEvictionPolicy(policy plainqv1alpha1.EvictionPolicy) string {
	switch policy {
	case plainqv1alpha1.EvictionDrop:
		return plainqapi.EvictionPolicyDrop

	case plainqv1alpha1.EvictionDeadLetter:
		return plainqapi.EvictionPolicyDeadLetter

	case plainqv1alpha1.EvictionReorder:
		return plainqapi.EvictionPolicyReorder
	}

	return ""
}
