package controller

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/plainqapi"
	"github.com/marsolab/plainq/operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ClientFactory hands out authenticated PlainQ API clients, one per instance,
// with their token caches kept warm across reconciles.
type ClientFactory struct {
	kube client.Client

	mu      sync.Mutex
	clients map[string]*plainqapi.Client
}

// NewClientFactory returns a factory backed by a Kubernetes client.
func NewClientFactory(kube client.Client) *ClientFactory {
	return &ClientFactory{kube: kube, clients: map[string]*plainqapi.Client{}}
}

// For returns a client for the instance a ServerReference names.
//
// For an instance the operator manages, credentials come from the bootstrap
// admin Secret it created. For an external endpoint they come from the
// Secret the user supplied.
func (f *ClientFactory) For(
	ctx context.Context,
	namespace string,
	ref plainqv1alpha1.ServerReference,
) (*plainqapi.Client, error) {
	endpoint, creds, err := f.resolve(ctx, namespace, ref)
	if err != nil {
		return nil, err
	}

	key := namespace + "/" + ref.Name + "|" + endpoint + "|" + creds.Email

	f.mu.Lock()
	defer f.mu.Unlock()

	if cached, ok := f.clients[key]; ok {
		return cached, nil
	}

	c := plainqapi.New(endpoint, plainqapi.WithCredentials(creds))
	f.clients[key] = c

	return c, nil
}

// Forget drops any cached client for an instance, so a credential rotation or
// a deletion does not leave a stale token behind.
func (f *ClientFactory) Forget(namespace, name string) {
	f.mu.Lock()
	defer f.mu.Unlock()

	prefix := namespace + "/" + name + "|"

	for key := range f.clients {
		if len(key) >= len(prefix) && key[:len(prefix)] == prefix {
			delete(f.clients, key)
		}
	}
}

func (f *ClientFactory) resolve(
	ctx context.Context,
	namespace string,
	ref plainqv1alpha1.ServerReference,
) (string, plainqapi.Credentials, error) {
	if ref.Endpoint != "" {
		if ref.CredentialsSecretRef == nil {
			return "", plainqapi.Credentials{},
				fmt.Errorf("serverRef.endpoint %q has no credentials", ref.Endpoint)
		}

		creds, err := f.credentials(ctx, namespace, *ref.CredentialsSecretRef)
		if err != nil {
			return "", plainqapi.Credentials{}, err
		}

		return ref.Endpoint, creds, nil
	}

	var pq plainqv1alpha1.PlainQ
	if err := f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, &pq); err != nil {
		return "", plainqapi.Credentials{}, fmt.Errorf("get PlainQ %s/%s: %w", namespace, ref.Name, err)
	}

	pq.Spec.ApplyDefaults()

	endpoint := fmt.Sprintf("http://%s:%d", render.NamesFor(&pq).ServiceFQDN(), pq.Spec.Listeners.HTTP.Port)

	// With auth disabled the server ignores the header, so an empty
	// credential is correct rather than an omission.
	if !plainqv1alpha1.BoolValue(pq.Spec.Auth.Enabled, true) {
		return endpoint, plainqapi.Credentials{}, nil
	}

	secretRef := adminSecretRef(&pq)

	creds, err := f.credentials(ctx, namespace, secretRef)
	if err != nil {
		return "", plainqapi.Credentials{}, err
	}

	return endpoint, creds, nil
}

func (f *ClientFactory) credentials(
	ctx context.Context,
	namespace string,
	ref plainqv1alpha1.CredentialsSecretReference,
) (plainqapi.Credentials, error) {
	var secret corev1.Secret

	if err := f.kube.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
		return plainqapi.Credentials{}, fmt.Errorf("get Secret %s/%s: %w", namespace, ref.Name, err)
	}

	emailKey := keyOr(ref.EmailKey, "email")
	passwordKey := keyOr(ref.PasswordKey, "password")

	email := string(secret.Data[emailKey])
	password := string(secret.Data[passwordKey])

	if email == "" || password == "" {
		return plainqapi.Credentials{}, fmt.Errorf(
			"Secret %s/%s is missing %q or %q", namespace, ref.Name, emailKey, passwordKey)
	}

	return plainqapi.Credentials{Email: email, Password: password}, nil
}

// adminSecretRef returns the bootstrap admin credential reference for an
// instance, generating the conventional name when none was supplied.
func adminSecretRef(pq *plainqv1alpha1.PlainQ) plainqv1alpha1.CredentialsSecretReference {
	if ref := pq.Spec.Bootstrap.AdminSecretRef; ref != nil && ref.Name != "" {
		return *ref
	}

	return plainqv1alpha1.CredentialsSecretReference{
		Name:        render.NamesFor(pq).AdminSecret(),
		EmailKey:    "email",
		PasswordKey: "password",
	}
}

func keyOr(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

// ensureSecret creates a Secret with generated values if it does not exist,
// and returns its data either way.
//
// Generated secrets are owned by the instance so they are garbage collected
// with it, and they are never regenerated once present: rotating a signing
// key on every reconcile would invalidate every session in flight.
func ensureSecret(
	ctx context.Context,
	kube client.Client,
	secret *corev1.Secret,
) (map[string][]byte, error) {
	var existing corev1.Secret

	err := kube.Get(ctx, client.ObjectKeyFromObject(secret), &existing)

	switch {
	case err == nil:
		return existing.Data, nil

	case !apierrors.IsNotFound(err):
		return nil, fmt.Errorf("get Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	if err := kube.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Lost a race with another reconcile. The existing value wins.
			if getErr := kube.Get(ctx, client.ObjectKeyFromObject(secret), &existing); getErr == nil {
				return existing.Data, nil
			}
		}

		return nil, fmt.Errorf("create Secret %s/%s: %w", secret.Namespace, secret.Name, err)
	}

	return secret.Data, nil
}

// randomHex returns a cryptographically random hex string of n bytes.
func randomHex(n int) (string, error) {
	buf := make([]byte, n)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// randomBase64 returns a cryptographically random base64 string of n bytes.
// The gossip key must be base64 of exactly 16, 24 or 32 bytes.
func randomBase64(n int) (string, error) {
	buf := make([]byte, n)

	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}
