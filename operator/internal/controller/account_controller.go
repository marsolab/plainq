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
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// PlainQAccountReconciler creates accounts on an instance.
type PlainQAccountReconciler struct {
	client.Client

	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
	Clients  *ClientFactory
}

// +kubebuilder:rbac:groups=plainq.dev,resources=plainqaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=plainq.dev,resources=plainqaccounts/status,verbs=get;update;patch

// Reconcile creates the account if it does not exist.
func (r *PlainQAccountReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var account plainqv1alpha1.PlainQAccount
	if err := r.Get(ctx, req.NamespacedName, &account); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if !account.DeletionTimestamp.IsZero() {
		// Accounts are retained by default and the server has no delete
		// route the operator uses, so deletion is a no-op beyond letting the
		// object go.
		return ctrl.Result{}, nil
	}

	api, err := r.Clients.For(ctx, account.Namespace, account.Spec.ServerRef)
	if err != nil {
		return r.report(ctx, &account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonServerUnreachable, err.Error())
	}

	password, err := r.ensurePassword(ctx, &account)
	if err != nil {
		return r.report(ctx, &account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonReconciling, err.Error())
	}

	if account.Spec.Bootstrap {
		return r.reconcileBootstrapAccount(ctx, &account, api, password)
	}

	return r.reconcileRegularAccount(ctx, &account, api, password)
}

// reconcileBootstrapAccount uses the onboarding endpoint, which works exactly
// once and then closes itself.
func (r *PlainQAccountReconciler) reconcileBootstrapAccount(
	ctx context.Context,
	account *plainqv1alpha1.PlainQAccount,
	api *plainqapi.Client,
	password string,
) (ctrl.Result, error) {
	status, err := api.OnboardingStatus(ctx)
	if err != nil {
		return r.report(ctx, account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonServerUnreachable, err.Error())
	}

	if !status.NeedsOnboarding {
		// Already done, by us on an earlier pass or by a human. Either way
		// the desired state holds.
		return r.report(ctx, account, metav1.ConditionTrue,
			plainqv1alpha1.ReasonAvailable, "an admin account already exists")
	}

	if err := api.CompleteOnboarding(ctx, account.Spec.Email, password, ""); err != nil {
		return r.report(ctx, account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonNotBootstrapped, err.Error())
	}

	r.Recorder.Eventf(account, corev1.EventTypeNormal, "AccountCreated",
		"created the first admin account %q", account.Spec.Email)

	return r.report(ctx, account, metav1.ConditionTrue,
		plainqv1alpha1.ReasonAvailable, "created the first admin account")
}

// reconcileRegularAccount creates an account through signup.
//
// That route refuses whenever the target instance has self-registration
// disabled — the handler checks the flag before it reads the body, and an
// admin token does not exempt it. The webhook rejects the combination up
// front; this is the belt-and-braces path for an instance whose setting
// changed after the account was admitted.
func (r *PlainQAccountReconciler) reconcileRegularAccount(
	ctx context.Context,
	account *plainqv1alpha1.PlainQAccount,
	api *plainqapi.Client,
	password string,
) (ctrl.Result, error) {
	existing, err := api.FindAccountByEmail(ctx, account.Spec.Email)

	switch {
	case err == nil:
		account.Status.AccountID = existing.ID

		return r.report(ctx, account, metav1.ConditionTrue,
			plainqv1alpha1.ReasonAvailable, "the account exists")

	case !errors.Is(err, plainqapi.ErrNotFound):
		return r.report(ctx, account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonServerUnreachable, err.Error())
	}

	if err := api.SignUp(ctx, account.Spec.Email, password, ""); err != nil {
		if errors.Is(err, plainqapi.ErrRegistrationDisabled) {
			message := "the target PlainQ has auth.registration disabled, and " +
				"/api/v1/account/signup is the only account-creation route the server has. " +
				"Enable registration on the instance, or use spec.bootstrap for the first admin."

			r.Recorder.Event(account, corev1.EventTypeWarning,
				plainqv1alpha1.ReasonRegistrationDisabled, message)

			// Not retryable: this is a configuration problem, so the object
			// waits rather than hammering a route that will keep refusing.
			return r.report(ctx, account, metav1.ConditionFalse,
				plainqv1alpha1.ReasonRegistrationDisabled, message)
		}

		return r.report(ctx, account, metav1.ConditionFalse,
			plainqv1alpha1.ReasonReconciling, err.Error())
	}

	r.Recorder.Eventf(account, corev1.EventTypeNormal, "AccountCreated",
		"created account %q", account.Spec.Email)

	if account.Spec.Role != "" && account.Spec.Role != "user" {
		if created, err := api.FindAccountByEmail(ctx, account.Spec.Email); err == nil {
			account.Status.AccountID = created.ID

			if err := api.AssignRole(ctx, created.ID, account.Spec.Role); err != nil {
				return r.report(ctx, account, metav1.ConditionFalse,
					plainqv1alpha1.ReasonReconciling,
					fmt.Sprintf("account created but role assignment failed: %v", err))
			}
		}
	}

	return r.report(ctx, account, metav1.ConditionTrue,
		plainqv1alpha1.ReasonAvailable, "the account exists")
}

// ensurePassword reads or generates the account password.
func (r *PlainQAccountReconciler) ensurePassword(
	ctx context.Context,
	account *plainqv1alpha1.PlainQAccount,
) (string, error) {
	ref := account.Spec.CredentialsSecretRef
	if ref == nil {
		ref = &plainqv1alpha1.CredentialsSecretReference{Name: account.Name + "-credentials"}
	}

	passwordKey := keyOr(ref.PasswordKey, "password")
	emailKey := keyOr(ref.EmailKey, "email")

	password, err := randomHex(24)
	if err != nil {
		return "", err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ref.Name,
			Namespace: account.Namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			emailKey:    []byte(account.Spec.Email),
			passwordKey: []byte(password),
		},
	}

	if err := controllerutilSetOwner(account, secret, r.Scheme); err != nil {
		return "", err
	}

	data, err := ensureSecret(ctx, r.Client, secret)
	if err != nil {
		return "", err
	}

	stored := string(data[passwordKey])
	if stored == "" {
		return "", fmt.Errorf("Secret %s has no %q", ref.Name, passwordKey)
	}

	return stored, nil
}

func (r *PlainQAccountReconciler) report(
	ctx context.Context,
	account *plainqv1alpha1.PlainQAccount,
	status metav1.ConditionStatus,
	reason, message string,
) (ctrl.Result, error) {
	account.Status.ObservedGeneration = account.Generation

	setCondition(&account.Status.Conditions, plainqv1alpha1.ConditionReady,
		status, reason, message, account.Generation)

	if err := r.Status().Update(ctx, account); err != nil {
		return ctrl.Result{}, fmt.Errorf("update status: %w", err)
	}

	if status == metav1.ConditionTrue {
		return ctrl.Result{RequeueAfter: requeueSteady}, nil
	}

	// A configuration problem is not going to fix itself in fifteen seconds.
	if reason == plainqv1alpha1.ReasonRegistrationDisabled {
		return ctrl.Result{RequeueAfter: requeueSteady}, nil
	}

	return ctrl.Result{RequeueAfter: requeueBackoff}, nil
}

// SetupWithManager registers the reconciler.
func (r *PlainQAccountReconciler) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).
		For(&plainqv1alpha1.PlainQAccount{}).
		Named("plainqaccount").
		Complete(r)
	if err != nil {
		return fmt.Errorf("build account controller: %w", err)
	}

	return nil
}
