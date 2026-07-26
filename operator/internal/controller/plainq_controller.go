package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/plainqapi"
	"github.com/marsolab/plainq/operator/internal/render"
	"github.com/marsolab/plainq/operator/internal/validation"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Requeue intervals. Provisioning is event-driven; the periodic passes exist
// to poll the PlainQ API, which does not send us anything.
const (
	requeueClusterPoll = 30 * time.Second
	requeueBackoff     = 15 * time.Second
	requeueSteady      = 2 * time.Minute
)

// plainqFinalizer lets the operator drop cached credentials and release an
// alias before an instance disappears.
const plainqFinalizer = "plainq.dev/finalizer"

// PlainQReconciler provisions and supervises PlainQ instances.
type PlainQReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder Recorder
	Clients  *ClientFactory
}

// +kubebuilder:rbac:groups=plainq.dev,resources=plainqs,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqs/finalizers,verbs=update
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=apps,resources=statefulsets;deployments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=services;persistentvolumeclaims;serviceaccounts;secrets;configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;rolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=autoscaling,resources=horizontalpodautoscalers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=networking.k8s.io,resources=ingresses;networkpolicies,verbs=get;list;watch;create;update;patch;delete

// Reconcile drives one instance toward its spec.
//
//nolint:cyclop // A reconcile loop is a sequence of guarded phases.
func (r *PlainQReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	var pq plainqv1alpha1.PlainQ
	if err := r.Get(ctx, req.NamespacedName, &pq); err != nil {
		return ctrl.Result{}, fmt.Errorf("get PlainQ: %w", client.IgnoreNotFound(err))
	}

	if !pq.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &pq)
	}

	if !controllerutilContainsFinalizer(&pq, plainqFinalizer) {
		controllerutilAddFinalizer(&pq, plainqFinalizer)

		if err := r.Update(ctx, &pq); err != nil {
			return ctrl.Result{}, fmt.Errorf("add finalizer: %w", err)
		}
	}

	// Defaulting is idempotent, and applying it here means the reconciler
	// behaves identically whether or not the mutating webhook is installed.
	pq.Spec.ApplyDefaults()

	if err := r.claimAlias(ctx, &pq); err != nil {
		r.setDegraded(&pq, plainqv1alpha1.ReasonAliasConflict, err.Error())

		if statusErr := r.updateStatus(ctx, &pq); statusErr != nil {
			return ctrl.Result{}, statusErr
		}

		r.Recorder.Event(&pq, corev1.EventTypeWarning, plainqv1alpha1.ReasonAliasConflict, err.Error())

		return ctrl.Result{RequeueAfter: requeueSteady}, nil
	}

	refs, err := r.ensureSecrets(ctx, &pq)
	if err != nil {
		return ctrl.Result{}, err
	}

	// A cluster scaling down is drained one node at a time before the
	// workload is allowed to shrink. Doing it the other way round removes
	// pods without removing voters, which is how a cluster loses quorum
	// with nobody having asked it to.
	drained, err := r.reconcileScaleIn(ctx, &pq)
	if err != nil {
		logger.Error(err, "supervised scale-in")
		r.Recorder.Event(&pq, corev1.EventTypeWarning, plainqv1alpha1.ReasonQuorumRisk, err.Error())

		return ctrl.Result{RequeueAfter: requeueBackoff}, nil
	}

	if drained {
		// A member left the configuration this pass. Come back to take the
		// next step rather than shrinking several at once.
		return ctrl.Result{RequeueAfter: requeueBackoff}, nil
	}

	if err := r.applyResources(ctx, &pq, refs); err != nil {
		return ctrl.Result{}, err
	}

	if err := r.reconcileBootstrap(ctx, &pq); err != nil {
		logger.V(1).Info("bootstrap not complete", "reason", err.Error())
	}

	r.observe(ctx, &pq)

	if err := r.updateStatus(ctx, &pq); err != nil {
		return ctrl.Result{}, err
	}

	if pq.Spec.Cluster.Enabled {
		return ctrl.Result{RequeueAfter: requeueClusterPoll}, nil
	}

	return ctrl.Result{RequeueAfter: requeueSteady}, nil
}

// applyResources renders and applies every object the instance needs.
//
//nolint:gocyclo,cyclop // One conditional per optional resource; splitting it would only scatter the list.
func (r *PlainQReconciler) applyResources(
	ctx context.Context,
	pq *plainqv1alpha1.PlainQ,
	refs render.SecretRefs,
) error {
	a := applier{client: r.Client, scheme: r.Scheme}

	if sa := render.ServiceAccount(pq); sa != nil {
		if err := a.apply(ctx, sa, pq); err != nil {
			return err
		}
	}

	if role := render.DiscoveryRole(pq); role != nil {
		if err := a.apply(ctx, role, pq); err != nil {
			return err
		}

		if err := a.apply(ctx, render.DiscoveryRoleBinding(pq), pq); err != nil {
			return err
		}
	}

	if err := a.apply(ctx, render.Service(pq), pq); err != nil {
		return err
	}

	if pq.Spec.Cluster.Enabled {
		if err := a.apply(ctx, render.HeadlessService(pq), pq); err != nil {
			return err
		}

		if plainqv1alpha1.BoolValue(pq.Spec.Cluster.PodDisruptionBudget.Enabled, true) {
			if err := a.apply(ctx, render.PodDisruptionBudget(pq), pq); err != nil {
				return err
			}
		}
	}

	if alias := render.AliasService(pq); alias != nil {
		// The alias deliberately carries an owner reference to whichever
		// instance holds it: it should disappear with the last holder, and
		// moving it re-parents it as part of the same atomic edit.
		if err := a.apply(ctx, alias, pq); err != nil {
			return err
		}
	}

	if err := r.applyWorkload(ctx, a, pq, refs); err != nil {
		return err
	}

	if ingress := render.Ingress(pq); ingress != nil {
		if err := a.apply(ctx, ingress, pq); err != nil {
			return err
		}
	}

	if policy := render.NetworkPolicy(pq); policy != nil {
		if err := a.apply(ctx, policy, pq); err != nil {
			return err
		}
	}

	if hpa := render.HorizontalPodAutoscaler(pq); hpa != nil {
		if err := a.apply(ctx, hpa, pq); err != nil {
			return err
		}
	}

	return nil
}

func (r *PlainQReconciler) applyWorkload(
	ctx context.Context,
	a applier,
	pq *plainqv1alpha1.PlainQ,
	refs render.SecretRefs,
) error {
	if pq.Spec.Storage.Driver == plainqv1alpha1.StoragePostgres {
		return a.apply(ctx, render.Deployment(pq, refs), pq)
	}

	persistence := pq.Spec.Storage.SQLite.Persistence

	// A standalone claim, only for a single node that is not adopting one.
	// Cluster nodes get a volumeClaimTemplate instead, and an adopted claim
	// is managed by whoever created it.
	if !pq.Spec.Cluster.Enabled &&
		plainqv1alpha1.BoolValue(persistence.Enabled, true) &&
		persistence.ExistingClaim == "" {
		if err := a.apply(ctx, render.PersistentVolumeClaim(pq), pq); err != nil {
			return err
		}
	}

	return a.apply(ctx, render.StatefulSet(pq, refs), pq)
}

// ensureSecrets generates the secrets the instance needs and returns the
// references the rendered pod reads them through.
//
//nolint:cyclop // A flat sequence of "supplied or generated?" decisions.
func (r *PlainQReconciler) ensureSecrets(
	ctx context.Context,
	pq *plainqv1alpha1.PlainQ,
) (render.SecretRefs, error) {
	names := render.NamesFor(pq)

	refs := render.SecretRefs{
		JWTSecretName:     names.JWTSecret(),
		JWTSecretKey:      "jwt-secret",
		ClusterSecretName: names.ClusterSecret(),
		GossipSecretKey:   "gossip-secret",
		ClusterSecretKey:  "cluster-secret",
	}

	if ref := pq.Spec.Auth.JWTSecretRef; ref != nil && ref.Name != "" {
		refs.JWTSecretName = ref.Name
		refs.JWTSecretKey = keyOr(ref.Key, "jwt-secret")
	} else if plainqv1alpha1.BoolValue(pq.Spec.Auth.Enabled, true) {
		secret, err := r.generatedSecret(pq, names.JWTSecret(), func() (map[string][]byte, error) {
			value, err := randomHex(32)
			if err != nil {
				return nil, err
			}

			return map[string][]byte{"jwt-secret": []byte(value)}, nil
		})
		if err != nil {
			return refs, err
		}

		if _, err := ensureSecret(ctx, r.Client, secret); err != nil {
			return refs, err
		}
	}

	if !pq.Spec.Cluster.Enabled {
		return refs, nil
	}

	if ref := pq.Spec.Cluster.SecretRef; ref != nil && ref.Name != "" {
		refs.ClusterSecretName = ref.Name
		refs.GossipSecretKey = keyOr(ref.GossipKey, "gossip-secret")
		refs.ClusterSecretKey = keyOr(ref.SecretKey, "cluster-secret")

		return refs, nil
	}

	secret, err := r.generatedSecret(pq, names.ClusterSecret(), func() (map[string][]byte, error) {
		// The gossip key must be base64 of 16, 24 or 32 bytes.
		gossip, err := randomBase64(32)
		if err != nil {
			return nil, err
		}

		peer, err := randomHex(32)
		if err != nil {
			return nil, err
		}

		return map[string][]byte{
			"gossip-secret":  []byte(gossip),
			"cluster-secret": []byte(peer),
		}, nil
	})
	if err != nil {
		return refs, err
	}

	if _, err := ensureSecret(ctx, r.Client, secret); err != nil {
		return refs, err
	}

	return refs, nil
}

func (r *PlainQReconciler) generatedSecret(
	pq *plainqv1alpha1.PlainQ,
	name string,
	build func() (map[string][]byte, error),
) (*corev1.Secret, error) {
	data, err := build()
	if err != nil {
		return nil, err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: pq.Namespace,
			Labels:    render.Labels(pq),
		},
		Type: corev1.SecretTypeOpaque,
		Data: data,
	}

	if err := controllerutilSetOwner(pq, secret, r.Scheme); err != nil {
		return nil, err
	}

	return secret, nil
}

// reconcileBootstrap creates the first admin account through the onboarding
// endpoint, so an unattended deployment can finish without a browser.
func (r *PlainQReconciler) reconcileBootstrap(ctx context.Context, pq *plainqv1alpha1.PlainQ) error {
	if !plainqv1alpha1.BoolValue(pq.Spec.Bootstrap.Enabled, true) ||
		!plainqv1alpha1.BoolValue(pq.Spec.Auth.Enabled, true) {
		return nil
	}

	ref := adminSecretRef(pq)

	// Generate credentials before anything tries to use them. The password
	// is written once and never rotated by the operator: rotating it would
	// lock the operator out of the instance it just provisioned.
	secret, err := r.generatedSecret(pq, ref.Name, func() (map[string][]byte, error) {
		password, err := randomHex(24)
		if err != nil {
			return nil, err
		}

		return map[string][]byte{
			keyOr(ref.EmailKey, "email"):       []byte(defaultAdminEmail(pq)),
			keyOr(ref.PasswordKey, "password"): []byte(password),
		}, nil
	})
	if err != nil {
		return err
	}

	data, err := ensureSecret(ctx, r.Client, secret)
	if err != nil {
		return err
	}

	api, err := r.Clients.For(ctx, pq.Namespace, plainqv1alpha1.ServerReference{Name: pq.Name})
	if err != nil {
		return err
	}

	status, err := api.OnboardingStatus(ctx)
	if err != nil {
		// The server is probably still starting. Not an error worth
		// reporting on its own; the condition below says what is true.
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionBootstrapped,
			metav1.ConditionFalse, plainqv1alpha1.ReasonServerUnreachable, err.Error(), pq.Generation)

		return fmt.Errorf("onboarding status: %w", err)
	}

	if !status.NeedsOnboarding {
		pq.Status.Bootstrap = &plainqv1alpha1.BootstrapStatus{Completed: true, AdminSecret: ref.Name}
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionBootstrapped,
			metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable, "admin account exists", pq.Generation)

		return nil
	}

	email := string(data[keyOr(ref.EmailKey, "email")])
	password := string(data[keyOr(ref.PasswordKey, "password")])

	if err := api.CompleteOnboarding(ctx, email, password, "PlainQ Operator"); err != nil {
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionBootstrapped,
			metav1.ConditionFalse, plainqv1alpha1.ReasonNotBootstrapped, err.Error(), pq.Generation)

		return fmt.Errorf("complete onboarding: %w", err)
	}

	r.Recorder.Eventf(pq, corev1.EventTypeNormal, "Bootstrapped",
		"created the first admin account %q", email)

	pq.Status.Bootstrap = &plainqv1alpha1.BootstrapStatus{Completed: true, AdminSecret: ref.Name}
	setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionBootstrapped,
		metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable, "admin account created", pq.Generation)

	return nil
}

func defaultAdminEmail(pq *plainqv1alpha1.PlainQ) string {
	return fmt.Sprintf("admin@%s.%s.svc", pq.Name, pq.Namespace)
}

// reconcileScaleIn performs at most one supervised removal per pass.
//
// The order matters and is the whole point: remove the voter from the Raft
// configuration first, wait for the configuration change to commit, and only
// then let the StatefulSet shrink. `kubectl scale` does the opposite, which
// is how a healthy cluster silently loses quorum.
//
// Each step is validated against the configuration as it stands now, not
// against the final replica count: quorum is recomputed after every committed
// change, so 3 -> 2 -> 1 is safe step by step even though 1 is below the
// quorum of 2 the cluster started with.
//
//nolint:cyclop // A linear drain sequence; each guard is a distinct precondition.
func (r *PlainQReconciler) reconcileScaleIn(ctx context.Context, pq *plainqv1alpha1.PlainQ) (bool, error) {
	if !pq.Spec.Cluster.Enabled {
		return false, nil
	}

	var sts appsv1.StatefulSet

	err := r.Get(ctx, client.ObjectKey{Namespace: pq.Namespace, Name: render.NamesFor(pq).Workload()}, &sts)
	if apierrors.IsNotFound(err) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("get statefulset: %w", err)
	}

	current := int32(1)
	if sts.Spec.Replicas != nil {
		current = *sts.Spec.Replicas
	}

	target := pq.Spec.Cluster.Replicas
	if target >= current {
		// Scale-out needs no supervision: new nodes discover the cluster and
		// the leader admits them.
		return false, nil
	}

	api, err := r.Clients.For(ctx, pq.Namespace, plainqv1alpha1.ServerReference{Name: pq.Name})
	if err != nil {
		return false, err
	}

	members, err := api.ClusterMembers(ctx)
	if err != nil {
		return false, fmt.Errorf("read membership before draining: %w", err)
	}

	counts := countVoters(members)

	// One step at a time: this pass removes exactly one member.
	step := current - 1
	if err := validation.ValidateScaleIn(counts.total, counts.healthy, step); err != nil {
		return false, fmt.Errorf("validate scale-in step: %w", err)
	}

	// Highest ordinal first, which is the pod the StatefulSet would remove.
	victim := render.NamesFor(pq).PodName(current - 1)

	if !memberPresent(members, victim) {
		// Already out of the configuration; letting the workload shrink is
		// now safe.
		return false, nil
	}

	if err := api.RemoveMember(ctx, victim); err != nil {
		return false, fmt.Errorf("remove voter %q: %w", victim, err)
	}

	r.Recorder.Eventf(pq, corev1.EventTypeNormal, "MemberRemoved",
		"removed %q from the consensus configuration before scaling in", victim)

	return true, nil
}

// voterCounts is how many voters the configuration holds and how many of
// them gossip can currently see. The gap between the two is what decides
// whether a membership change can commit.
type voterCounts struct {
	total   int32
	healthy int32
}

func countVoters(members []plainqapi.ClusterMember) voterCounts {
	var counts voterCounts

	for _, m := range members {
		if !m.IsVoter() {
			continue
		}

		counts.total++

		if m.Reachable {
			counts.healthy++
		}
	}

	return counts
}

func memberPresent(members []plainqapi.ClusterMember, id string) bool {
	for _, m := range members {
		if m.ID == id {
			return true
		}
	}

	return false
}

// claimAlias rejects a second instance claiming an alias another already
// holds. An alias with two holders is not a cutover.
func (r *PlainQReconciler) claimAlias(ctx context.Context, pq *plainqv1alpha1.PlainQ) error {
	alias := pq.Spec.Networking.Alias.Name
	if alias == "" {
		return nil
	}

	var siblings plainqv1alpha1.PlainQList
	if err := r.List(ctx, &siblings, client.InNamespace(pq.Namespace)); err != nil {
		return fmt.Errorf("list instances: %w", err)
	}

	for i := range siblings.Items {
		other := &siblings.Items[i]

		if other.Name == pq.Name || other.Spec.Networking.Alias.Name != alias {
			continue
		}

		// Deterministic tie-break: the older claim wins, so two objects
		// created at once cannot deadlock each other.
		if other.CreationTimestamp.Before(&pq.CreationTimestamp) {
			return fmt.Errorf("alias %q is already held by PlainQ %q", alias, other.Name)
		}
	}

	return nil
}

// observe reads live state into status.
func (r *PlainQReconciler) observe(ctx context.Context, pq *plainqv1alpha1.PlainQ) {
	names := render.NamesFor(pq)

	pq.Status.ObservedGeneration = pq.Generation
	pq.Status.Version = pq.Spec.Version
	pq.Status.Replicas = pq.Spec.DesiredReplicas()
	pq.Status.Endpoint = names.ServiceFQDN()
	pq.Status.GRPCEndpoint = net.JoinHostPort(names.ServiceFQDN(),
		strconv.Itoa(int(pq.Spec.Listeners.GRPC.Port)))
	pq.Status.HTTPEndpoint = "http://" + net.JoinHostPort(names.ServiceFQDN(),
		strconv.Itoa(int(pq.Spec.Listeners.HTTP.Port)))
	pq.Status.Storage = &plainqv1alpha1.StorageStatus{Driver: pq.Spec.Storage.Driver}

	pq.Status.ReadyReplicas = r.readyReplicas(ctx, pq)

	if pq.Spec.Cluster.Enabled {
		r.observeCluster(ctx, pq)
	}

	r.setPhase(pq)
}

func (r *PlainQReconciler) readyReplicas(ctx context.Context, pq *plainqv1alpha1.PlainQ) int32 {
	key := client.ObjectKey{Namespace: pq.Namespace, Name: render.NamesFor(pq).Workload()}

	if pq.Spec.Storage.Driver == plainqv1alpha1.StoragePostgres {
		var deploy appsv1.Deployment
		if err := r.Get(ctx, key, &deploy); err != nil {
			return 0
		}

		return deploy.Status.ReadyReplicas
	}

	var sts appsv1.StatefulSet
	if err := r.Get(ctx, key, &sts); err != nil {
		return 0
	}

	return sts.Status.ReadyReplicas
}

func (r *PlainQReconciler) observeCluster(ctx context.Context, pq *plainqv1alpha1.PlainQ) {
	api, err := r.Clients.For(ctx, pq.Namespace, plainqv1alpha1.ServerReference{Name: pq.Name})
	if err != nil {
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionClusterFormed,
			metav1.ConditionFalse, plainqv1alpha1.ReasonServerUnreachable, err.Error(), pq.Generation)

		return
	}

	status, err := api.ClusterStatus(ctx)
	if err != nil {
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionClusterFormed,
			metav1.ConditionFalse, plainqv1alpha1.ReasonServerUnreachable, err.Error(), pq.Generation)

		return
	}

	clusterStatus := &plainqv1alpha1.ClusterStatus{
		Formed: status.Healthy && status.LeaderID != "",
		Leader: status.LeaderID,
		//nolint:gosec // A quorum is bounded by the member count; it cannot overflow int32.
		Quorum: int32(status.Quorum),
	}

	for _, m := range status.Members {
		if m.IsVoter() {
			clusterStatus.Voters++
		} else if m.Suffrage == plainqapi.SuffrageNonVoter {
			clusterStatus.NonVoters++
		}

		clusterStatus.Members = append(clusterStatus.Members, plainqv1alpha1.ClusterMemberStatus{
			ID:        m.ID,
			Address:   m.Addr,
			Status:    m.Suffrage,
			Voter:     m.IsVoter(),
			Reachable: m.Reachable,
		})
	}

	pq.Status.Cluster = clusterStatus

	if clusterStatus.Formed {
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionClusterFormed,
			metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable,
			fmt.Sprintf("leader %s, %d voters", clusterStatus.Leader, clusterStatus.Voters), pq.Generation)

		return
	}

	setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionClusterFormed,
		metav1.ConditionFalse, plainqv1alpha1.ReasonQuorumRisk,
		fmt.Sprintf("no leader or quorum: %d voters, quorum %d",
			clusterStatus.Voters, clusterStatus.Quorum), pq.Generation)
}

func (r *PlainQReconciler) setPhase(pq *plainqv1alpha1.PlainQ) {
	desired := pq.Spec.DesiredReplicas()
	ready := pq.Status.ReadyReplicas

	switch {
	case pq.Spec.Cluster.Enabled && pq.Status.Cluster != nil && !pq.Status.Cluster.Formed:
		pq.Status.Phase = plainqv1alpha1.PhaseDegraded
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionReady,
			metav1.ConditionFalse, plainqv1alpha1.ReasonQuorumRisk,
			"the cluster has no leader", pq.Generation)

	case ready == 0:
		pq.Status.Phase = plainqv1alpha1.PhaseProvisioning
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionReady,
			metav1.ConditionFalse, plainqv1alpha1.ReasonReconciling,
			"waiting for pods", pq.Generation)

	case ready < desired:
		pq.Status.Phase = plainqv1alpha1.PhaseDegraded
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionReady,
			metav1.ConditionFalse, plainqv1alpha1.ReasonReconciling,
			fmt.Sprintf("%d of %d replicas ready", ready, desired), pq.Generation)

	default:
		pq.Status.Phase = plainqv1alpha1.PhaseRunning
		setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionReady,
			metav1.ConditionTrue, plainqv1alpha1.ReasonAvailable,
			"serving", pq.Generation)
	}

	setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionProgressing,
		boolCondition(pq.Status.Phase != plainqv1alpha1.PhaseRunning),
		plainqv1alpha1.ReasonReconciling, string(pq.Status.Phase), pq.Generation)
}

func (r *PlainQReconciler) setDegraded(pq *plainqv1alpha1.PlainQ, reason, message string) {
	pq.Status.Phase = plainqv1alpha1.PhaseDegraded

	setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionDegraded,
		metav1.ConditionTrue, reason, message, pq.Generation)
	setCondition(&pq.Status.Conditions, plainqv1alpha1.ConditionReady,
		metav1.ConditionFalse, reason, message, pq.Generation)
}

func (r *PlainQReconciler) updateStatus(ctx context.Context, pq *plainqv1alpha1.PlainQ) error {
	if err := r.Status().Update(ctx, pq); err != nil {
		if apierrors.IsConflict(err) {
			// Another writer won. The next pass will re-derive status.
			return nil
		}

		return fmt.Errorf("update status: %w", err)
	}

	return nil
}

func (r *PlainQReconciler) finalize(ctx context.Context, pq *plainqv1alpha1.PlainQ) (ctrl.Result, error) {
	if !controllerutilContainsFinalizer(pq, plainqFinalizer) {
		return ctrl.Result{}, nil
	}

	// Owned objects are garbage collected by Kubernetes. All that is left is
	// the operator's own cached credential for this instance.
	r.Clients.Forget(pq.Namespace, pq.Name)

	controllerutilRemoveFinalizer(pq, plainqFinalizer)

	if err := r.Update(ctx, pq); err != nil {
		return ctrl.Result{}, fmt.Errorf("remove finalizer: %w", err)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager registers the reconciler.
func (r *PlainQReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&plainqv1alpha1.PlainQ{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&appsv1.Deployment{}).
		Owns(&corev1.Service{}).
		Named("plainq").
		Complete(r)
	if err != nil {
		return fmt.Errorf("build plainq controller: %w", err)
	}

	return nil
}

// errServerNotReady marks a dependency that is expected to resolve on a later
// pass, so callers can requeue quietly rather than log an error.
var errServerNotReady = errors.New("plainq instance is not serving yet")
