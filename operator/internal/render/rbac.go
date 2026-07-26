package render

import (
	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ServiceAccount renders the identity the instance pods run as.
func ServiceAccount(pq *plainqv1alpha1.PlainQ) *corev1.ServiceAccount {
	if !plainqv1alpha1.BoolValue(pq.Spec.Pod.ServiceAccount.Create, true) {
		return nil
	}

	if pq.Spec.Pod.ServiceAccount.Name != "" {
		// An explicit name means the account is managed elsewhere.
		return nil
	}

	automount := needsServiceAccountToken(pq)

	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        NamesFor(pq).ServiceAccount(),
			Namespace:   pq.Namespace,
			Labels:      Labels(pq),
			Annotations: pq.Spec.Pod.ServiceAccount.Annotations,
		},
		AutomountServiceAccountToken: &automount,
	}
}

// DiscoveryRole grants exactly what Kubernetes peer discovery needs: reading
// this namespace's pods and endpoints. Nothing more, and nothing at all for
// DNS discovery, which needs no API access.
func DiscoveryRole(pq *plainqv1alpha1.PlainQ) *rbacv1.Role {
	if !needsServiceAccountToken(pq) {
		return nil
	}

	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      NamesFor(pq).Role(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "endpoints"},
				Verbs:     []string{"get", "list", "watch"},
			},
		},
	}
}

// DiscoveryRoleBinding binds the discovery Role to the instance's account.
func DiscoveryRoleBinding(pq *plainqv1alpha1.PlainQ) *rbacv1.RoleBinding {
	if !needsServiceAccountToken(pq) {
		return nil
	}

	names := NamesFor(pq)

	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.RoleBinding(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "Role",
			Name:     names.Role(),
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      rbacv1.ServiceAccountKind,
				Name:      serviceAccountName(pq),
				Namespace: pq.Namespace,
			},
		},
	}
}

// HorizontalPodAutoscaler renders autoscaling for a Postgres-backed instance.
//
// It is deliberately absent for SQLite: that backend is single-writer on one
// volume, so scaling it is not slow, it is wrong.
func HorizontalPodAutoscaler(pq *plainqv1alpha1.PlainQ) *autoscalingv2.HorizontalPodAutoscaler {
	spec := pq.Spec.Autoscaling

	if !spec.Enabled || pq.Spec.Storage.Driver != plainqv1alpha1.StoragePostgres {
		return nil
	}

	names := NamesFor(pq)
	minReplicas := spec.MinReplicas

	hpa := &autoscalingv2.HorizontalPodAutoscaler{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.HorizontalPodAutoscaler(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: autoscalingv2.HorizontalPodAutoscalerSpec{
			ScaleTargetRef: autoscalingv2.CrossVersionObjectReference{
				APIVersion: "apps/v1",
				Kind:       "Deployment",
				Name:       names.Workload(),
			},
			MinReplicas: &minReplicas,
			MaxReplicas: spec.MaxReplicas,
		},
	}

	if target := spec.TargetCPUUtilizationPercentage; target > 0 {
		hpa.Spec.Metrics = append(hpa.Spec.Metrics, resourceMetric(corev1.ResourceCPU, target))
	}

	if target := spec.TargetMemoryUtilizationPercentage; target > 0 {
		hpa.Spec.Metrics = append(hpa.Spec.Metrics, resourceMetric(corev1.ResourceMemory, target))
	}

	return hpa
}

func resourceMetric(name corev1.ResourceName, target int32) autoscalingv2.MetricSpec {
	value := target

	return autoscalingv2.MetricSpec{
		Type: autoscalingv2.ResourceMetricSourceType,
		Resource: &autoscalingv2.ResourceMetricSource{
			Name: name,
			Target: autoscalingv2.MetricTarget{
				Type:               autoscalingv2.UtilizationMetricType,
				AverageUtilization: &value,
			},
		},
	}
}
