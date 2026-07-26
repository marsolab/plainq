// Package render turns a PlainQ spec into the Kubernetes objects that run it.
//
// It is a port of the Helm chart's templates: the same argument construction,
// the same $(VAR) secret indirection, the same discovery spec. The chart is
// the conformance target, so the two provisioning paths cannot drift apart.
package render

import (
	"fmt"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
)

// Label keys the operator owns.
const (
	LabelName      = "app.kubernetes.io/name"
	LabelInstance  = "app.kubernetes.io/instance"
	LabelComponent = "app.kubernetes.io/component"
	LabelManagedBy = "app.kubernetes.io/managed-by"
	LabelVersion   = "app.kubernetes.io/version"
	LabelPartOf    = "app.kubernetes.io/part-of"

	// LabelAlias marks the alias Service so its holder can be found.
	LabelAlias = "plainq.dev/alias"

	// AnnotationRestoredFrom records which restore produced an instance.
	// It is an annotation rather than an owner reference on purpose: the
	// restore record is an operation log people clean up, and cleaning it up
	// must never cascade into a live database.
	AnnotationRestoredFrom = "plainq.dev/restored-from"

	// AnnotationSecretChecksum rolls pods when a referenced Secret changes.
	AnnotationSecretChecksum = "plainq.dev/secret-checksum"

	// ManagedBy identifies the operator as the field manager.
	ManagedBy = "plainq-operator"

	// AppName is the common application name.
	AppName = "plainq"
)

// Names derives every resource name for one instance, so the naming scheme
// lives in one place rather than being spelled out at each call site.
type Names struct {
	// Instance is the PlainQ object name.
	Instance string

	// Namespace the instance lives in.
	Namespace string
}

// NamesFor returns the naming helper for an instance.
func NamesFor(pq *plainqv1alpha1.PlainQ) Names {
	return Names{Instance: pq.Name, Namespace: pq.Namespace}
}

// Base is the common prefix for generated resources.
func (n Names) Base() string { return n.Instance }

// Service is the client-facing Service name.
func (n Names) Service() string { return n.Instance }

// Headless is the Service that gives cluster pods stable DNS.
func (n Names) Headless() string { return n.Instance + "-headless" }

// Workload is the StatefulSet or Deployment name.
func (n Names) Workload() string { return n.Instance }

// PVC is the data volume for a single-node instance. Cluster instances use a
// volumeClaimTemplate, which Kubernetes names per pod.
func (n Names) PVC() string { return n.Instance + "-data" }

// JWTSecret holds the generated token-signing secret.
func (n Names) JWTSecret() string { return n.Instance + "-jwt" }

// ClusterSecret holds the generated gossip and peer-RPC secrets.
func (n Names) ClusterSecret() string { return n.Instance + "-cluster" }

// AdminSecret holds the generated bootstrap admin credentials.
func (n Names) AdminSecret() string { return n.Instance + "-admin" }

// AgentSecret holds the bearer token the operator uses to reach the backup
// agent sidecar.
func (n Names) AgentSecret() string { return n.Instance + "-agent" }

// ServiceAccount for the instance pods.
func (n Names) ServiceAccount() string { return n.Instance }

// Role granting Kubernetes discovery the reads it needs.
func (n Names) Role() string { return n.Instance + "-discovery" }

// RoleBinding for the discovery Role.
func (n Names) RoleBinding() string { return n.Instance + "-discovery" }

// PodDisruptionBudget for a cluster.
func (n Names) PodDisruptionBudget() string { return n.Instance }

// HorizontalPodAutoscaler for a Postgres-backed instance.
func (n Names) HorizontalPodAutoscaler() string { return n.Instance }

// Ingress for the instance.
func (n Names) Ingress() string { return n.Instance }

// NetworkPolicy for the instance.
func (n Names) NetworkPolicy() string { return n.Instance }

// ServiceMonitor for Prometheus Operator scraping.
func (n Names) ServiceMonitor() string { return n.Instance }

// PrometheusRule holding the bundled alerts.
func (n Names) PrometheusRule() string { return n.Instance }

// GrafanaDashboard ConfigMap.
func (n Names) GrafanaDashboard() string { return n.Instance + "-dashboard" }

// PodFQDN returns the in-cluster DNS name of one cluster pod.
func (n Names) PodFQDN(ordinal int32) string {
	return fmt.Sprintf("%s-%d.%s.%s.svc", n.Workload(), ordinal, n.Headless(), n.Namespace)
}

// PodName returns the StatefulSet pod name for an ordinal. It is also the
// node's cluster identity, because a StatefulSet pod name is both stable
// across restarts and unique in the cluster.
func (n Names) PodName(ordinal int32) string {
	return fmt.Sprintf("%s-%d", n.Workload(), ordinal)
}

// ServiceFQDN returns the in-cluster DNS name of the client Service.
func (n Names) ServiceFQDN() string {
	return fmt.Sprintf("%s.%s.svc", n.Service(), n.Namespace)
}

// SelectorLabels are the labels that identify an instance's pods. They are
// immutable for the life of a StatefulSet, so nothing version-dependent may
// appear here.
func SelectorLabels(pq *plainqv1alpha1.PlainQ) map[string]string {
	return map[string]string{
		LabelName:     AppName,
		LabelInstance: pq.Name,
	}
}

// Labels are the selector labels plus descriptive ones.
func Labels(pq *plainqv1alpha1.PlainQ) map[string]string {
	labels := SelectorLabels(pq)
	labels[LabelManagedBy] = ManagedBy
	labels[LabelPartOf] = AppName

	if version := pq.Spec.Version; version != "" {
		labels[LabelVersion] = version
	}

	return labels
}

// MergeLabels combines label maps left to right, later maps winning.
func MergeLabels(maps ...map[string]string) map[string]string {
	merged := map[string]string{}

	for _, m := range maps {
		for k, v := range m {
			merged[k] = v
		}
	}

	return merged
}
