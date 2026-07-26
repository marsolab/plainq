package render

import (
	"path/filepath"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Volume and container names.
const (
	dataVolumeName    = "data"
	tmpVolumeName     = "tmp"
	tlsVolumeName     = "cluster-tls"
	serverContainer   = "plainq"
	grpcPortName      = "grpc"
	httpPortName      = "http"
	clusterPortName   = "cluster"
	gossipTCPPortName = "gossip-tcp"
	gossipUDPPortName = "gossip-udp"
)

// StatefulSet renders the workload for a SQLite-backed instance, clustered or
// not.
//
// A single node is one replica with one PersistentVolumeClaim: SQLite is a
// single-file embedded database and cannot be shared. In a cluster each pod
// owns its own database and the nodes replicate between themselves, so the
// single-writer constraint no longer caps the deployment at one pod — hence
// volumeClaimTemplates rather than a shared claim.
func StatefulSet(pq *plainqv1alpha1.PlainQ, refs SecretRefs) *appsv1.StatefulSet {
	names := NamesFor(pq)
	replicas := pq.Spec.DesiredReplicas()

	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.Workload(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: appsv1.StatefulSetSpec{
			Replicas:    &replicas,
			ServiceName: names.Headless(),
			Selector:    &metav1.LabelSelector{MatchLabels: SelectorLabels(pq)},
			Template:    podTemplate(pq, refs),
		},
	}

	if pq.Spec.Cluster.Enabled {
		// Pods come up together rather than one at a time: bootstrap-expect
		// waits for all of them to be visible before forming a cluster, and
		// OrderedReady would deadlock waiting for a readiness that cannot
		// arrive until they are.
		sts.Spec.PodManagementPolicy = appsv1.ParallelPodManagement
	}

	// A quorum-aware roll is driven by the operator rather than the
	// StatefulSet controller: it has to wait for each node to rejoin as a
	// voter and restart the leader last, which OnDelete makes possible.
	if pq.Spec.Cluster.Enabled && plainqv1alpha1.BoolValue(pq.Spec.UpdateStrategy.QuorumAware, true) {
		sts.Spec.UpdateStrategy = appsv1.StatefulSetUpdateStrategy{
			Type: appsv1.OnDeleteStatefulSetStrategyType,
		}
	} else if pq.Spec.UpdateStrategy.Type == plainqv1alpha1.UpdateOnDelete {
		sts.Spec.UpdateStrategy = appsv1.StatefulSetUpdateStrategy{
			Type: appsv1.OnDeleteStatefulSetStrategyType,
		}
	}

	persistence := pq.Spec.Storage.SQLite.Persistence

	switch {
	case !plainqv1alpha1.BoolValue(persistence.Enabled, true):
		// No persistence: the data directory is an emptyDir, added by
		// podVolumes below.

	case pq.Spec.Cluster.Enabled:
		sts.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{
			*dataClaim(pq, dataVolumeName),
		}

	case persistence.ExistingClaim != "":
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: dataVolumeName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: persistence.ExistingClaim,
				},
			},
		})

	default:
		// A standalone claim rather than a template, so the operator can
		// adopt a volume left behind by the Helm chart.
		sts.Spec.Template.Spec.Volumes = append(sts.Spec.Template.Spec.Volumes, corev1.Volume{
			Name: dataVolumeName,
			VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
					ClaimName: names.PVC(),
				},
			},
		})
	}

	return sts
}

// Deployment renders the workload for a Postgres-backed instance, which holds
// no local state and can therefore scale horizontally.
func Deployment(pq *plainqv1alpha1.PlainQ, refs SecretRefs) *appsv1.Deployment {
	names := NamesFor(pq)
	replicas := pq.Spec.DesiredReplicas()

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.Workload(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: SelectorLabels(pq)},
			Template: podTemplate(pq, refs),
		},
	}
}

// PersistentVolumeClaim renders the standalone data volume for a single-node
// SQLite instance.
func PersistentVolumeClaim(pq *plainqv1alpha1.PlainQ) *corev1.PersistentVolumeClaim {
	claim := dataClaim(pq, NamesFor(pq).PVC())
	claim.Namespace = pq.Namespace

	return claim
}

func dataClaim(pq *plainqv1alpha1.PlainQ, name string) *corev1.PersistentVolumeClaim {
	persistence := pq.Spec.Storage.SQLite.Persistence

	size := persistence.Size
	if size == "" {
		size = plainqv1alpha1.DefaultVolumeSize
	}

	quantity := resource.MustParse(size)

	accessModes := persistence.AccessModes
	if len(accessModes) == 0 {
		accessModes = []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce}
	}

	claim := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Labels:      Labels(pq),
			Annotations: persistence.Annotations,
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: accessModes,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceStorage: quantity},
			},
		},
	}

	if class := persistence.StorageClassName; class != "" {
		claim.Spec.StorageClassName = &class
	}

	return claim
}

func podTemplate(pq *plainqv1alpha1.PlainQ, refs SecretRefs) corev1.PodTemplateSpec {
	spec := pq.Spec

	podSpec := corev1.PodSpec{
		ServiceAccountName:            serviceAccountName(pq),
		SecurityContext:               spec.Pod.SecurityContext,
		Containers:                    append([]corev1.Container{serverContainerSpec(pq, refs)}, spec.Pod.Sidecars...),
		InitContainers:                spec.Pod.InitContainers,
		Volumes:                       podVolumes(pq),
		NodeSelector:                  spec.Pod.NodeSelector,
		Tolerations:                   spec.Pod.Tolerations,
		Affinity:                      spec.Pod.Affinity,
		TopologySpreadConstraints:     spec.Pod.TopologySpreadConstraints,
		PriorityClassName:             spec.Pod.PriorityClassName,
		TerminationGracePeriodSeconds: spec.Pod.TerminationGracePeriodSeconds,
		ImagePullSecrets:              spec.Image.PullSecrets,
	}

	// Kubernetes discovery authenticates to the API with the mounted service
	// account. Without the token the pod cannot find its peers, so the mount
	// is turned on here rather than left to a field someone has to know to
	// set. Every other configuration leaves it off.
	if needsServiceAccountToken(pq) {
		podSpec.AutomountServiceAccountToken = boolPtr(true)
	} else {
		podSpec.AutomountServiceAccountToken = boolPtr(false)
	}

	return corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      MergeLabels(SelectorLabels(pq), spec.Pod.Labels),
			Annotations: MergeLabels(map[string]string{}, spec.Pod.Annotations),
		},
		Spec: podSpec,
	}
}

func serverContainerSpec(pq *plainqv1alpha1.PlainQ, refs SecretRefs) corev1.Container {
	spec := pq.Spec

	container := corev1.Container{
		Name:            serverContainer,
		Image:           spec.ImageRef(),
		ImagePullPolicy: spec.Image.PullPolicy,
		Args:            ServeArgs(pq),
		Env:             PodEnv(pq, refs),
		EnvFrom:         spec.Pod.EnvFrom,
		SecurityContext: spec.Pod.ContainerSecurityContext,
		Resources:       spec.Pod.Resources,
		Ports:           containerPorts(pq),
		VolumeMounts:    containerMounts(pq),
		LivenessProbe:   probeOr(spec.Pod.LivenessProbe, defaultProbe(pq, 10, 15)),
		ReadinessProbe:  probeOr(spec.Pod.ReadinessProbe, defaultProbe(pq, 5, 10)),
		StartupProbe:    spec.Pod.StartupProbe,
	}

	return container
}

func containerPorts(pq *plainqv1alpha1.PlainQ) []corev1.ContainerPort {
	ports := []corev1.ContainerPort{
		{Name: grpcPortName, ContainerPort: pq.Spec.Listeners.GRPC.Port, Protocol: corev1.ProtocolTCP},
		{Name: httpPortName, ContainerPort: pq.Spec.Listeners.HTTP.Port, Protocol: corev1.ProtocolTCP},
	}

	if pq.Spec.Cluster.Enabled {
		ports = append(ports,
			corev1.ContainerPort{
				Name: clusterPortName, ContainerPort: pq.Spec.Cluster.ClusterPort, Protocol: corev1.ProtocolTCP,
			},
			corev1.ContainerPort{
				Name: gossipTCPPortName, ContainerPort: pq.Spec.Cluster.GossipPort, Protocol: corev1.ProtocolTCP,
			},
			// Gossip runs over both transports on the same port number.
			corev1.ContainerPort{
				Name: gossipUDPPortName, ContainerPort: pq.Spec.Cluster.GossipPort, Protocol: corev1.ProtocolUDP,
			},
		)
	}

	return ports
}

func containerMounts(pq *plainqv1alpha1.PlainQ) []corev1.VolumeMount {
	// /tmp is writable scratch space, required because the root filesystem
	// is read-only.
	mounts := []corev1.VolumeMount{{Name: tmpVolumeName, MountPath: "/tmp"}}

	if pq.Spec.Storage.Driver == plainqv1alpha1.StorageSQLite {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      dataVolumeName,
			MountPath: filepath.Dir(pq.Spec.Storage.SQLite.Path),
		})
	}

	if pq.Spec.Cluster.Enabled && pq.Spec.Cluster.TLS != nil && pq.Spec.Cluster.TLS.SecretRef != nil {
		mounts = append(mounts, corev1.VolumeMount{
			Name:      tlsVolumeName,
			MountPath: clusterTLSMountPath,
			ReadOnly:  true,
		})
	}

	return append(mounts, pq.Spec.Pod.ExtraVolumeMounts...)
}

func podVolumes(pq *plainqv1alpha1.PlainQ) []corev1.Volume {
	volumes := []corev1.Volume{
		{Name: tmpVolumeName, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
	}

	persistence := pq.Spec.Storage.SQLite.Persistence

	if pq.Spec.Storage.Driver == plainqv1alpha1.StorageSQLite &&
		!plainqv1alpha1.BoolValue(persistence.Enabled, true) {
		volumes = append(volumes, corev1.Volume{
			Name:         dataVolumeName,
			VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
		})
	}

	if pq.Spec.Cluster.Enabled && pq.Spec.Cluster.TLS != nil && pq.Spec.Cluster.TLS.SecretRef != nil {
		volumes = append(volumes, corev1.Volume{
			Name: tlsVolumeName,
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{SecretName: pq.Spec.Cluster.TLS.SecretRef.Name},
			},
		})
	}

	return append(volumes, pq.Spec.Pod.ExtraVolumes...)
}

func defaultProbe(pq *plainqv1alpha1.PlainQ, initialDelay, period int32) *corev1.Probe {
	route := pq.Spec.Observability.Health.Route
	if route == "" {
		route = plainqv1alpha1.DefaultHealthRoute
	}

	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path: route,
				Port: intstr.FromString(httpPortName),
			},
		},
		InitialDelaySeconds: initialDelay,
		PeriodSeconds:       period,
		TimeoutSeconds:      3,
		FailureThreshold:    3,
	}
}

func probeOr(override, fallback *corev1.Probe) *corev1.Probe {
	if override != nil {
		return override
	}

	return fallback
}

// needsServiceAccountToken reports whether the pod has to talk to the
// Kubernetes API. Only Kubernetes discovery does.
func needsServiceAccountToken(pq *plainqv1alpha1.PlainQ) bool {
	return pq.Spec.Cluster.Enabled && pq.Spec.Cluster.Discovery == plainqv1alpha1.DiscoveryKubernetes
}

func serviceAccountName(pq *plainqv1alpha1.PlainQ) string {
	if name := pq.Spec.Pod.ServiceAccount.Name; name != "" {
		return name
	}

	if !plainqv1alpha1.BoolValue(pq.Spec.Pod.ServiceAccount.Create, true) {
		return "default"
	}

	return NamesFor(pq).ServiceAccount()
}

// PodDisruptionBudget renders a budget derived from quorum: a cluster of N
// voters may lose N - quorum members and keep serving, so that is the most
// voluntary disruption allowed at once.
func PodDisruptionBudget(pq *plainqv1alpha1.PlainQ) *policyv1.PodDisruptionBudget {
	replicas := pq.Spec.Cluster.Replicas
	tolerable := replicas - plainqv1alpha1.Quorum(replicas)

	if tolerable < 1 {
		// A single-node or two-node cluster tolerates no voluntary
		// disruption at all without losing quorum.
		tolerable = 0
	}

	maxUnavailable := intstr.FromInt32(tolerable)

	return &policyv1.PodDisruptionBudget{
		ObjectMeta: metav1.ObjectMeta{
			Name:      NamesFor(pq).PodDisruptionBudget(),
			Namespace: pq.Namespace,
			Labels:    Labels(pq),
		},
		Spec: policyv1.PodDisruptionBudgetSpec{
			MaxUnavailable: &maxUnavailable,
			Selector:       &metav1.LabelSelector{MatchLabels: SelectorLabels(pq)},
		},
	}
}

func boolPtr(v bool) *bool { return &v }
