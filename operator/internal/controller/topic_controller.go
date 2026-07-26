package controller

import (
	"context"
	"errors"
	"fmt"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/plainqapi"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const topicFinalizer = "plainq.dev/topic-finalizer"

// PlainQTopicReconciler keeps topics and their fan-out matching their objects.
type PlainQTopicReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder Recorder
	Clients  *ClientFactory
}

// +kubebuilder:rbac:groups=plainq.dev,resources=plainqtopics,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqtopics/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqtopics/finalizers,verbs=update

// Reconcile creates the topic and converges its subscriptions.
//
//nolint:cyclop // A reconcile loop is a sequence of guarded phases.
func (r *PlainQTopicReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var topic plainqv1alpha1.PlainQTopic
	if err := r.Get(ctx, req.NamespacedName, &topic); err != nil {
		return ctrl.Result{}, fmt.Errorf("get PlainQTopic: %w", client.IgnoreNotFound(err))
	}

	api, err := r.Clients.For(ctx, topic.Namespace, topic.Spec.ServerRef)
	if err != nil {
		if !topic.DeletionTimestamp.IsZero() {
			return r.dropFinalizer(ctx, &topic)
		}

		return r.reportWaiting(ctx, &topic, err)
	}

	if !topic.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &topic, api)
	}

	if !controllerutilContainsFinalizer(&topic, topicFinalizer) {
		controllerutilAddFinalizer(&topic, topicFinalizer)

		if err := r.Update(ctx, &topic); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	existing, err := api.ResolveTopicByName(ctx, topic.ResolvedTopicName())

	switch {
	case errors.Is(err, plainqapi.ErrNotFound):
		id, createErr := api.CreateTopic(ctx, topic.ResolvedTopicName())
		if createErr != nil {
			return r.reportWaiting(ctx, &topic, createErr)
		}

		r.Recorder.Eventf(&topic, corev1.EventTypeNormal, "TopicCreated",
			"created topic %q as %s", topic.ResolvedTopicName(), id)

		topic.Status.TopicID = id
		existing = &plainqapi.Topic{TopicID: id, TopicName: topic.ResolvedTopicName()}

	case err != nil:
		return r.reportWaiting(ctx, &topic, err)

	default:
		topic.Status.TopicID = existing.TopicID
	}

	if err := r.reconcileSubscriptions(ctx, &topic, api, existing); err != nil {
		return r.reportWaiting(ctx, &topic, err)
	}

	topic.Status.ObservedGeneration = topic.Generation

	setCondition(&topic.Status.Conditions, plainqv1alpha1.ConditionReady,
		metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable,
		"the topic exists and its subscriptions match spec", topic.Generation)

	if err := r.Status().Update(ctx, &topic); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueSteady}, nil
}

// reconcileSubscriptions converges the subscription set: subscribe what spec
// asks for and the server lacks, unsubscribe what the server has and spec
// does not.
func (r *PlainQTopicReconciler) reconcileSubscriptions(
	ctx context.Context,
	topic *plainqv1alpha1.PlainQTopic,
	api *plainqapi.Client,
	existing *plainqapi.Topic,
) error {
	desired, err := r.desiredQueueIDs(ctx, topic)
	if err != nil {
		return err
	}

	current := map[string]string{}
	for _, sub := range existing.Subscriptions {
		current[sub.QueueID] = sub.SubscriptionID
	}

	var status []plainqv1alpha1.SubscriptionStatus

	for _, want := range desired {
		subscriptionID, ok := current[want.queueID]

		if !ok {
			subscriptionID, err = api.Subscribe(ctx, existing.TopicID, want.queueID)
			if err != nil {
				return fmt.Errorf("subscribe: %w", err)
			}

			r.Recorder.Eventf(topic, corev1.EventTypeNormal, "Subscribed",
				"subscribed queue %s to topic %q", want.queueID, topic.ResolvedTopicName())
		}

		status = append(status, plainqv1alpha1.SubscriptionStatus{
			Queue:          want.objectName,
			QueueID:        want.queueID,
			SubscriptionID: subscriptionID,
			Ready:          true,
		})

		delete(current, want.queueID)
	}

	// Whatever is left was removed from spec.
	for queueID, subscriptionID := range current {
		if err := api.Unsubscribe(ctx, existing.TopicID, subscriptionID); err != nil {
			return fmt.Errorf("unsubscribe: %w", err)
		}

		r.Recorder.Eventf(topic, corev1.EventTypeNormal, "Unsubscribed",
			"unsubscribed queue %s from topic %q", queueID, topic.ResolvedTopicName())
	}

	topic.Status.Subscriptions = status

	return nil
}

// desiredSubscription is one resolved subscription target.
type desiredSubscription struct {
	// objectName is the PlainQQueue name, empty for a raw ID.
	objectName string
	queueID    string
}

func (r *PlainQTopicReconciler) desiredQueueIDs(
	ctx context.Context,
	topic *plainqv1alpha1.PlainQTopic,
) ([]desiredSubscription, error) {
	desired := make([]desiredSubscription, 0, len(topic.Spec.Subscriptions))

	for _, sub := range topic.Spec.Subscriptions {
		if sub.QueueID != "" {
			desired = append(desired, desiredSubscription{queueID: sub.QueueID})

			continue
		}

		if sub.QueueRef == nil {
			continue
		}

		var queue plainqv1alpha1.PlainQQueue

		key := client.ObjectKey{Namespace: topic.Namespace, Name: sub.QueueRef.Name}
		if err := r.Get(ctx, key, &queue); err != nil {
			return nil, fmt.Errorf("subscription queue %q: %w", sub.QueueRef.Name, err)
		}

		// Same dependency rule as dead-letter references: wait for the
		// queue to exist rather than failing on apply order.
		if queue.Status.QueueID == "" {
			return nil, fmt.Errorf("%w: queue %q has no id yet", errServerNotReady, sub.QueueRef.Name)
		}

		desired = append(desired, desiredSubscription{
			objectName: queue.Name,
			queueID:    queue.Status.QueueID,
		})
	}

	return desired, nil
}

func (r *PlainQTopicReconciler) finalize(
	ctx context.Context,
	topic *plainqv1alpha1.PlainQTopic,
	api *plainqapi.Client,
) (ctrl.Result, error) {
	if !controllerutilContainsFinalizer(topic, topicFinalizer) {
		return ctrl.Result{}, nil
	}

	if topic.Spec.DeletionPolicy == plainqv1alpha1.DeletionDelete && topic.Status.TopicID != "" {
		if err := api.DeleteTopic(ctx, topic.Status.TopicID); err != nil {
			return ctrl.Result{}, fmt.Errorf("delete topic: %w", err)
		}

		r.Recorder.Eventf(topic, corev1.EventTypeNormal, "TopicDeleted",
			"deleted topic %q", topic.ResolvedTopicName())
	}

	return r.dropFinalizer(ctx, topic)
}

func (r *PlainQTopicReconciler) dropFinalizer(
	ctx context.Context,
	topic *plainqv1alpha1.PlainQTopic,
) (ctrl.Result, error) {
	if !controllerutilContainsFinalizer(topic, topicFinalizer) {
		return ctrl.Result{}, nil
	}

	controllerutilRemoveFinalizer(topic, topicFinalizer)

	if err := r.Update(ctx, topic); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

func (r *PlainQTopicReconciler) reportWaiting(
	ctx context.Context,
	topic *plainqv1alpha1.PlainQTopic,
	cause error,
) (ctrl.Result, error) {
	reason := plainqv1alpha1.ReasonServerUnreachable
	if errors.Is(cause, errServerNotReady) {
		reason = plainqv1alpha1.ReasonWaitingForDependency
	}

	setCondition(&topic.Status.Conditions, plainqv1alpha1.ConditionReady,
		metav1.ConditionFalse, reason, cause.Error(), topic.Generation)

	if err := r.Status().Update(ctx, topic); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	return ctrl.Result{RequeueAfter: requeueBackoff}, nil
}

// SetupWithManager registers the reconciler.
func (r *PlainQTopicReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&plainqv1alpha1.PlainQTopic{}).
		Named("plainqtopic").
		Complete(r)
	if err != nil {
		return fmt.Errorf("build topic controller: %w", err)
	}

	return nil
}
