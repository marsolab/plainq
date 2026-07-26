package render_test

import (
	"slices"
	"strings"
	"testing"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"github.com/marsolab/plainq/operator/internal/render"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// instance builds a defaulted PlainQ, the way the webhook would hand one to
// the reconciler.
func instance(t *testing.T, mutate func(pq *plainqv1alpha1.PlainQ)) *plainqv1alpha1.PlainQ {
	t.Helper()

	pq := &plainqv1alpha1.PlainQ{
		ObjectMeta: metav1.ObjectMeta{Name: "orders", Namespace: "plainq"},
		Spec:       plainqv1alpha1.PlainQSpec{Version: "1.4.0"},
	}

	if mutate != nil {
		mutate(pq)
	}

	pq.Spec.ApplyDefaults()

	return pq
}

func defaultRefs() render.SecretRefs {
	return render.SecretRefs{
		JWTSecretName:     "orders-jwt",
		JWTSecretKey:      "jwt-secret",
		ClusterSecretName: "orders-cluster",
		GossipSecretKey:   "gossip-secret",
		ClusterSecretKey:  "cluster-secret",
	}
}

func hasArg(args []string, want string) bool { return slices.Contains(args, want) }

func argValue(t *testing.T, args []string, name string) string {
	t.Helper()

	prefix := "-" + name + "="

	for _, arg := range args {
		if strings.HasPrefix(arg, prefix) {
			return strings.TrimPrefix(arg, prefix)
		}
	}

	t.Fatalf("flag -%s not found in %v", name, args)

	return ""
}

func TestServeArgsNeverInlineSecrets(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
	})

	args := render.ServeArgs(pq)

	// Every secret must be a $(VAR) reference the kubelet expands, never a
	// literal. A literal would end up in the rendered manifest and in every
	// audit log that captured it.
	for _, name := range []string{"auth.jwt.secret", "cluster.gossip.secret", "cluster.secret"} {
		value := argValue(t, args, name)
		if !strings.HasPrefix(value, "$(") || !strings.HasSuffix(value, ")") {
			t.Errorf("-%s = %q, want a $(VAR) reference", name, value)
		}
	}
}

func TestServeArgsSingleNodeSQLite(t *testing.T) {
	t.Parallel()

	pq := instance(t, nil)
	args := render.ServeArgs(pq)

	if got := args[0]; got != "serve" {
		t.Fatalf("first arg %q, want serve", got)
	}

	if got := argValue(t, args, "storage.driver"); got != "sqlite" {
		t.Errorf("storage.driver = %q, want sqlite", got)
	}

	if got := argValue(t, args, "storage.path"); got != "/data/plainq.db" {
		t.Errorf("storage.path = %q", got)
	}

	if got := argValue(t, args, "grpc.addr"); got != ":8080" {
		t.Errorf("grpc.addr = %q", got)
	}

	if got := argValue(t, args, "http.addr"); got != ":8081" {
		t.Errorf("http.addr = %q", got)
	}

	// Clustering is off, so none of its flags may leak in.
	for _, arg := range args {
		if strings.HasPrefix(arg, "-cluster.") {
			t.Errorf("unexpected cluster flag on a single node: %s", arg)
		}
	}
}

func TestServeArgsPostgresUsesDSNReference(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Storage.Driver = plainqv1alpha1.StoragePostgres
		pq.Spec.Storage.Postgres.DSNSecretRef = &plainqv1alpha1.SecretKeyReference{
			Name: "orders-pg", Key: "dsn",
		}
	})

	args := render.ServeArgs(pq)

	if got := argValue(t, args, "storage.postgres.dsn"); got != "$(PLAINQ_POSTGRES_DSN)" {
		t.Errorf("storage.postgres.dsn = %q, want a variable reference", got)
	}

	// The SQLite path is meaningless here and must not be emitted.
	if hasArg(args, "-storage.path=/data/plainq.db") {
		t.Error("storage.path emitted for the postgres driver")
	}
}

func TestClusterArgsMatchTheChart(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Cluster.Replicas = 5
	})

	args := render.ServeArgs(pq)

	want := map[string]string{
		"cluster.enable":                "true",
		"cluster.node-id":               "$(PLAINQ_NODE_ID)",
		"cluster.bind.addr":             "0.0.0.0:8082",
		"cluster.advertise.addr":        "$(PLAINQ_POD_IP):8082",
		"cluster.gossip.addr":           "0.0.0.0:8083",
		"cluster.gossip.advertise.addr": "$(PLAINQ_POD_IP):8083",
		// bootstrap-expect defaults to the replica count: all nodes must be
		// visible before the cluster forms.
		"cluster.bootstrap-expect": "5",
		"cluster.consistency":      "local",
	}

	for name, expected := range want {
		if got := argValue(t, args, name); got != expected {
			t.Errorf("-%s = %q, want %q", name, got, expected)
		}
	}
}

func TestDiscoverySpecKubernetesSelectsThisInstance(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
	})

	spec := render.DiscoverySpec(pq)

	if !strings.HasPrefix(spec, "kubernetes://") {
		t.Fatalf("discovery spec %q, want the kubernetes provider", spec)
	}

	// The selector must be URL-escaped: it contains commas and slashes that
	// would otherwise terminate the query parameter.
	if strings.Contains(spec, "selector=app.kubernetes.io/name") {
		t.Errorf("selector is not escaped: %s", spec)
	}

	for _, want := range []string{"namespace=$(PLAINQ_NAMESPACE)", "port=8083"} {
		if !strings.Contains(spec, want) {
			t.Errorf("discovery spec %q missing %q", spec, want)
		}
	}
}

func TestDiscoverySpecDNSUsesHeadlessService(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Cluster.Discovery = plainqv1alpha1.DiscoveryDNS
	})

	spec := render.DiscoverySpec(pq)

	if !strings.HasPrefix(spec, "dns://orders-headless.") {
		t.Fatalf("discovery spec %q, want the headless service", spec)
	}
}

func TestDiscoverySpecCustomIsVerbatim(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Cluster.Discovery = plainqv1alpha1.DiscoveryCustom
		pq.Spec.Cluster.DiscoverySpec = "static://10.0.0.1:8083,10.0.0.2:8083"
	})

	if got := render.DiscoverySpec(pq); got != "static://10.0.0.1:8083,10.0.0.2:8083" {
		t.Fatalf("discovery spec %q, want the verbatim override", got)
	}
}

func TestSQLiteIsPinnedToOneReplicaOutsideCluster(t *testing.T) {
	t.Parallel()

	// SQLite is single-writer on one ReadWriteOnce volume. Asking for five
	// replicas is not a scaling decision, it is data corruption, so the
	// spec is pinned rather than obeyed.
	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Replicas = 5
	})

	if got := pq.Spec.DesiredReplicas(); got != 1 {
		t.Fatalf("desired replicas %d, want 1", got)
	}

	sts := render.StatefulSet(pq, defaultRefs())
	if *sts.Spec.Replicas != 1 {
		t.Fatalf("statefulset replicas %d, want 1", *sts.Spec.Replicas)
	}
}

func TestClusterStatefulSetUsesParallelPodManagement(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
	})

	sts := render.StatefulSet(pq, defaultRefs())

	// OrderedReady would deadlock: bootstrap-expect waits for every node to
	// be visible, and no node is ready until the cluster forms.
	if sts.Spec.PodManagementPolicy != "Parallel" {
		t.Errorf("pod management %q, want Parallel", sts.Spec.PodManagementPolicy)
	}

	if len(sts.Spec.VolumeClaimTemplates) != 1 {
		t.Fatalf("volume claim templates %d, want 1 (each node owns its database)",
			len(sts.Spec.VolumeClaimTemplates))
	}
}

func TestQuorumAwareRollUsesOnDelete(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
	})

	sts := render.StatefulSet(pq, defaultRefs())

	// The operator drives the roll itself so it can wait for each node to
	// rejoin as a voter and restart the leader last.
	if sts.Spec.UpdateStrategy.Type != "OnDelete" {
		t.Fatalf("update strategy %q, want OnDelete for a quorum-aware roll", sts.Spec.UpdateStrategy.Type)
	}
}

func TestSingleNodeAdoptsAnExistingClaim(t *testing.T) {
	t.Parallel()

	// This is the migration path off the Helm chart: same volume, no data
	// movement.
	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Storage.SQLite.Persistence.ExistingClaim = "plainq-data"
	})

	sts := render.StatefulSet(pq, defaultRefs())

	var found bool

	for _, v := range sts.Spec.Template.Spec.Volumes {
		if v.PersistentVolumeClaim != nil && v.PersistentVolumeClaim.ClaimName == "plainq-data" {
			found = true
		}
	}

	if !found {
		t.Fatalf("existing claim not mounted; volumes: %+v", sts.Spec.Template.Spec.Volumes)
	}

	if len(sts.Spec.VolumeClaimTemplates) != 0 {
		t.Error("a claim template was rendered alongside an adopted claim")
	}
}

func TestServiceAccountTokenOnlyMountedForKubernetesDiscovery(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(pq *plainqv1alpha1.PlainQ)
		want   bool
	}{
		"single node": {
			mutate: func(*plainqv1alpha1.PlainQ) {},
			want:   false,
		},
		"cluster with kubernetes discovery": {
			mutate: func(pq *plainqv1alpha1.PlainQ) { pq.Spec.Cluster.Enabled = true },
			want:   true,
		},
		"cluster with dns discovery": {
			mutate: func(pq *plainqv1alpha1.PlainQ) {
				pq.Spec.Cluster.Enabled = true
				pq.Spec.Cluster.Discovery = plainqv1alpha1.DiscoveryDNS
			},
			want: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pq := instance(t, tc.mutate)
			sts := render.StatefulSet(pq, defaultRefs())

			got := sts.Spec.Template.Spec.AutomountServiceAccountToken
			if got == nil {
				t.Fatal("automountServiceAccountToken left unset; it should be explicit")
			}

			if *got != tc.want {
				t.Errorf("automount = %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestDiscoveryRoleOnlyForKubernetesDiscovery(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Cluster.Discovery = plainqv1alpha1.DiscoveryDNS
	})

	if role := render.DiscoveryRole(pq); role != nil {
		t.Error("a discovery Role was rendered for DNS discovery, which needs no API access")
	}

	pq = instance(t, func(pq *plainqv1alpha1.PlainQ) { pq.Spec.Cluster.Enabled = true })

	role := render.DiscoveryRole(pq)
	if role == nil {
		t.Fatal("no discovery Role for kubernetes discovery")
	}

	// The grant must stay minimal: pods and endpoints, read-only.
	for _, rule := range role.Rules {
		for _, verb := range rule.Verbs {
			if verb != "get" && verb != "list" && verb != "watch" {
				t.Errorf("discovery Role grants %q; it should be read-only", verb)
			}
		}
	}
}

func TestPodDisruptionBudgetDerivesFromQuorum(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		replicas int32
		want     int32
	}{
		// 3 voters, quorum 2, so one may go.
		"three nodes": {replicas: 3, want: 1},
		// 5 voters, quorum 3, so two may go.
		"five nodes": {replicas: 5, want: 2},
		// 1 voter is its own quorum: no voluntary disruption at all.
		"single node": {replicas: 1, want: 0},
		// 2 voters have a quorum of 2, so losing either loses the cluster.
		"two nodes": {replicas: 2, want: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
				pq.Spec.Cluster.Enabled = true
				pq.Spec.Cluster.Replicas = tc.replicas
			})

			pdb := render.PodDisruptionBudget(pq)
			if got := pdb.Spec.MaxUnavailable.IntVal; got != tc.want {
				t.Fatalf("maxUnavailable %d, want %d", got, tc.want)
			}
		})
	}
}

func TestHardenedSecurityContextByDefault(t *testing.T) {
	t.Parallel()

	pq := instance(t, nil)
	sts := render.StatefulSet(pq, defaultRefs())

	pod := sts.Spec.Template.Spec

	if pod.SecurityContext == nil || !*pod.SecurityContext.RunAsNonRoot {
		t.Error("pod security context is not runAsNonRoot")
	}

	// fsGroup is what makes the mounted volume writable by the nonroot user.
	if pod.SecurityContext.FSGroup == nil {
		t.Error("fsGroup unset; the data volume would not be writable")
	}

	container := pod.Containers[0]

	if container.SecurityContext == nil || !*container.SecurityContext.ReadOnlyRootFilesystem {
		t.Error("container root filesystem is not read-only")
	}

	// A read-only root filesystem needs writable scratch space somewhere.
	var hasTmp bool

	for _, mount := range container.VolumeMounts {
		if mount.MountPath == "/tmp" {
			hasTmp = true
		}
	}

	if !hasTmp {
		t.Error("no writable /tmp alongside a read-only root filesystem")
	}
}

func TestHeadlessServicePublishesNotReadyAddresses(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) { pq.Spec.Cluster.Enabled = true })

	svc := render.HeadlessService(pq)

	// A forming cluster has no ready pods: every node is waiting to see its
	// peers. Without this the members can never find each other.
	if !svc.Spec.PublishNotReadyAddresses {
		t.Error("headless service does not publish not-ready addresses")
	}

	if svc.Spec.ClusterIP != corev1.ClusterIPNone {
		t.Errorf("clusterIP %q, want None", svc.Spec.ClusterIP)
	}
}

func TestAliasServiceSelectsTheClaimingInstance(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Networking.Alias.Name = "orders-rw"
	})

	svc := render.AliasService(pq)
	if svc == nil {
		t.Fatal("no alias service rendered")
	}

	if svc.Name != "orders-rw" {
		t.Errorf("alias name %q", svc.Name)
	}

	// The alias points at this instance's pods, which is what makes moving
	// it a cutover.
	if svc.Spec.Selector[render.LabelInstance] != "orders" {
		t.Errorf("alias selector %v does not select this instance", svc.Spec.Selector)
	}

	if svc.Labels[render.LabelAlias] != "orders-rw" {
		t.Error("alias service is not labelled with the alias name, so its holder cannot be found")
	}
}

func TestNoAliasServiceWhenUnset(t *testing.T) {
	t.Parallel()

	if svc := render.AliasService(instance(t, nil)); svc != nil {
		t.Fatal("an alias service was rendered without an alias name")
	}
}

func TestHPAOnlyForPostgres(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Autoscaling.Enabled = true
		pq.Spec.Autoscaling.MinReplicas = 2
		pq.Spec.Autoscaling.MaxReplicas = 5
		pq.Spec.Autoscaling.TargetCPUUtilizationPercentage = 80
	})

	// Autoscaling a single-writer SQLite instance is not slow, it is wrong.
	if hpa := render.HorizontalPodAutoscaler(pq); hpa != nil {
		t.Error("an HPA was rendered for the sqlite driver")
	}

	pq.Spec.Storage.Driver = plainqv1alpha1.StoragePostgres

	hpa := render.HorizontalPodAutoscaler(pq)
	if hpa == nil {
		t.Fatal("no HPA rendered for the postgres driver")
	}

	if hpa.Spec.MaxReplicas != 5 {
		t.Errorf("maxReplicas %d, want 5", hpa.Spec.MaxReplicas)
	}
}

func TestNetworkPolicyOpensClusterPortsToPeers(t *testing.T) {
	t.Parallel()

	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Networking.NetworkPolicy.Enabled = true
		pq.Spec.Networking.NetworkPolicy.AllowFrom = []plainqv1alpha1.NetworkPolicyPeer{
			{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"plainq.dev/client": "true"}}},
		}
	})

	policy := render.NetworkPolicy(pq)
	if policy == nil {
		t.Fatal("no network policy rendered")
	}

	// Two rules: clients reaching the listeners, and peers reaching each
	// other. Without the second, enabling the policy breaks consensus.
	if len(policy.Spec.Ingress) != 2 {
		t.Fatalf("ingress rules %d, want 2 (clients and peers)", len(policy.Spec.Ingress))
	}

	var udp bool

	for _, port := range policy.Spec.Ingress[1].Ports {
		if port.Protocol != nil && *port.Protocol == corev1.ProtocolUDP {
			udp = true
		}
	}

	if !udp {
		t.Error("gossip UDP is not allowed between peers")
	}
}

func TestArgsAreStableAcrossRenders(t *testing.T) {
	t.Parallel()

	// Rendering is called on every reconcile. If map iteration leaked into
	// the argument order, every pass would look like a spec change and roll
	// the pods forever.
	pq := instance(t, func(pq *plainqv1alpha1.PlainQ) {
		pq.Spec.Cluster.Enabled = true
		pq.Spec.Listeners.HTTP.ReadTimeout = "5s"
		pq.Spec.Listeners.HTTP.WriteTimeout = "30s"
		pq.Spec.Listeners.HTTP.IdleTimeout = "120s"
		pq.Spec.Listeners.HTTP.ReadHeaderTimeout = "2s"
	})

	first := render.ServeArgs(pq)

	for range 20 {
		if got := render.ServeArgs(pq); !slices.Equal(got, first) {
			t.Fatalf("args are not stable:\n first: %v\nlater: %v", first, got)
		}
	}
}

func TestSelectorLabelsCarryNothingMutable(t *testing.T) {
	t.Parallel()

	// A StatefulSet selector is immutable. Anything version-dependent in it
	// would make an upgrade impossible without deleting the workload.
	pq := instance(t, nil)

	for key := range render.SelectorLabels(pq) {
		if key == render.LabelVersion {
			t.Error("the version label is in the immutable selector")
		}
	}
}
