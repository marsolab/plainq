package render

import (
	"fmt"
	"net/url"
	"path"
	"strconv"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// Environment variable names used for the $(VAR) indirection below.
const (
	EnvJWTSecret     = "PLAINQ_JWT_SECRET"
	EnvPostgresDSN   = "PLAINQ_POSTGRES_DSN"
	EnvNodeID        = "PLAINQ_NODE_ID"
	EnvPodIP         = "PLAINQ_POD_IP"
	EnvNamespace     = "PLAINQ_NAMESPACE"
	EnvGossipSecret  = "PLAINQ_GOSSIP_SECRET"
	EnvClusterSecret = "PLAINQ_CLUSTER_SECRET"
)

// ServeArgs builds the argument list for the serve subcommand.
//
// Secrets are never inlined. PlainQ reads configuration from flags rather
// than the environment, so a secret value is exposed as an environment
// variable and referenced from the flag as $(VAR). Kubernetes expands those
// references in container args itself — a kubelet feature, not a shell one,
// so it works on a distroless image with no shell. The expanded value never
// appears in the rendered manifest, only the reference does.
//
//nolint:cyclop,funlen // A flag builder is a flat list of conditionals.
func ServeArgs(pq *plainqv1alpha1.PlainQ) []string {
	spec := pq.Spec

	args := []string{
		"serve",
		flag("grpc.addr", ":"+strconv.Itoa(int(spec.Listeners.GRPC.Port))),
		flag("http.addr", ":"+strconv.Itoa(int(spec.Listeners.HTTP.Port))),
		flag("storage.driver", string(spec.Storage.Driver)),
	}

	if spec.Storage.Driver == plainqv1alpha1.StorageSQLite {
		args = append(args, flag("storage.path", spec.Storage.SQLite.Path))

		if mode := spec.Storage.SQLite.JournalMode; mode != "" {
			args = append(args, flag("storage.journal-mode", mode))
		}

		if mode := spec.Storage.SQLite.AccessMode; mode != "" {
			args = append(args, flag("storage.access-mode", mode))
		}
	} else {
		args = append(args, flag("storage.postgres.dsn", ref(EnvPostgresDSN)))
	}

	if timeout := spec.Storage.GC.Timeout; timeout != "" {
		args = append(args, flag("storage.gc.timeout", timeout))
	}

	if spec.Storage.Log {
		args = append(args, flag("storage.log.enable", "true"))
	}

	args = append(args, httpTimeoutArgs(spec)...)
	args = append(args, authArgs(spec)...)
	args = append(args, loggingArgs(spec)...)
	args = append(args, observabilityArgs(spec)...)
	args = append(args, telemetryArgs(spec)...)

	if !plainqv1alpha1.BoolValue(spec.Server.CORS, true) {
		args = append(args, flag("cors", "false"))
	}

	if spec.Server.Profiler {
		args = append(args, flag("profiler", "true"))
	}

	if spec.Cluster.Enabled {
		args = append(args, ClusterArgs(pq)...)
	}

	return append(args, spec.ExtraArgs...)
}

func httpTimeoutArgs(spec plainqv1alpha1.PlainQSpec) []string {
	var args []string

	for name, value := range map[string]string{
		"http.read-timeout":        spec.Listeners.HTTP.ReadTimeout,
		"http.read-header-timeout": spec.Listeners.HTTP.ReadHeaderTimeout,
		"http.write-timeout":       spec.Listeners.HTTP.WriteTimeout,
		"http.idle-timeout":        spec.Listeners.HTTP.IdleTimeout,
	} {
		if value != "" {
			args = append(args, flag(name, value))
		}
	}

	// Map iteration is random; the args have to be stable or every
	// reconcile would look like a change.
	sortStrings(args)

	return args
}

func authArgs(spec plainqv1alpha1.PlainQSpec) []string {
	if !plainqv1alpha1.BoolValue(spec.Auth.Enabled, true) {
		return []string{flag("auth.enable", "false")}
	}

	args := []string{
		flag("auth.enable", "true"),
		flag("auth.jwt.secret", ref(EnvJWTSecret)),
	}

	if ttl := spec.Auth.AccessTokenTTL; ttl != "" {
		args = append(args, flag("auth.access.ttl", ttl))
	}

	if ttl := spec.Auth.RefreshTokenTTL; ttl != "" {
		args = append(args, flag("auth.refresh.ttl", ttl))
	}

	args = append(args,
		flag("auth.registration.enable", boolString(plainqv1alpha1.BoolValue(spec.Auth.Registration, true))),
		flag("auth.email.verification.enable",
			boolString(plainqv1alpha1.BoolValue(spec.Auth.EmailVerification, true))),
	)

	return args
}

func loggingArgs(spec plainqv1alpha1.PlainQSpec) []string {
	return []string{
		flag("log.enable", boolString(plainqv1alpha1.BoolValue(spec.Logging.Enabled, true))),
		flag("log.access.enable", boolString(plainqv1alpha1.BoolValue(spec.Logging.AccessLogs, true))),
		flag("log.level", spec.Logging.Level),
	}
}

func observabilityArgs(spec plainqv1alpha1.PlainQSpec) []string {
	args := []string{
		flag("health", boolString(plainqv1alpha1.BoolValue(spec.Observability.Health.Enabled, true))),
		flag("health.route", spec.Observability.Health.Route),
		flag("metrics", boolString(plainqv1alpha1.BoolValue(spec.Observability.Metrics.Enabled, true))),
		flag("metrics.route", spec.Observability.Metrics.Route),
	}

	if spec.Observability.Health.Logs {
		args = append(args, flag("health.route.logs", "true"))
	}

	if spec.Observability.Health.Metrics {
		args = append(args, flag("health.route.metrics", "true"))
	}

	if reporter := spec.Observability.Health.Reporter; reporter != "" {
		args = append(args, flag("health.reporter", reporter))
	}

	if spec.Observability.Metrics.Logs {
		args = append(args, flag("metrics.route.logs", "true"))
	}

	if spec.Observability.Metrics.Metrics {
		args = append(args, flag("metrics.route.metrics", "true"))
	}

	return args
}

func telemetryArgs(spec plainqv1alpha1.PlainQSpec) []string {
	if !plainqv1alpha1.BoolValue(spec.Telemetry.Enabled, true) {
		return []string{flag("telemetry.enable", "false")}
	}

	args := []string{flag("telemetry.enable", "true")}

	if provider := spec.Telemetry.Provider; provider != "" {
		args = append(args, flag("telemetry.provider", provider))
	}

	if v := spec.Telemetry.CollectionInterval; v != "" {
		args = append(args, flag("telemetry.sqlite.collection.timeout", v))
	}

	if v := spec.Telemetry.GCInterval; v != "" {
		args = append(args, flag("telemetry.sqlite.gc.timeout", v))
	}

	if v := spec.Telemetry.RetentionPeriod; v != "" {
		args = append(args, flag("telemetry.sqlite.retention.period", v))
	}

	if v := spec.Telemetry.PrometheusBaseURL; v != "" {
		args = append(args, flag("telemetry.prometheus.baseurl", v))
	}

	if spec.Telemetry.Log {
		args = append(args, flag("telemetry.log.enable", "true"))
	}

	return args
}

// ClusterArgs builds the -cluster.* flags.
//
// Discovery answers with gossip addresses; a peer's consensus address is part
// of what it gossips, so only one port has to be discoverable.
//
//nolint:cyclop,funlen // A flag builder is a flat list of conditionals.
func ClusterArgs(pq *plainqv1alpha1.PlainQ) []string {
	c := pq.Spec.Cluster

	args := []string{
		flag("cluster.enable", "true"),
		flag("cluster.node-id", ref(EnvNodeID)),
		flag("cluster.bind.addr", "0.0.0.0:"+strconv.Itoa(int(c.ClusterPort))),
		flag("cluster.advertise.addr", ref(EnvPodIP)+":"+strconv.Itoa(int(c.ClusterPort))),
		flag("cluster.gossip.addr", "0.0.0.0:"+strconv.Itoa(int(c.GossipPort))),
		flag("cluster.gossip.advertise.addr", ref(EnvPodIP)+":"+strconv.Itoa(int(c.GossipPort))),
		flag("cluster.bootstrap-expect", strconv.Itoa(int(c.BootstrapExpect))),
		flag("cluster.consistency", string(c.Consistency)),
		flag("cluster.discovery", DiscoverySpec(pq)),
		flag("cluster.auto-remove", boolString(c.AutoRemove)),
		flag("cluster.remove.timeout", c.RemoveTimeout),
		flag("cluster.data.dir", c.DataDir),
	}

	if c.NonVoter {
		args = append(args, flag("cluster.non-voter", "true"))
	}

	if v := c.DiscoveryInterval; v != "" {
		args = append(args, flag("cluster.discovery.interval", v))
	}

	if v := c.ReconcileInterval; v != "" {
		args = append(args, flag("cluster.reconcile.interval", v))
	}

	if v := c.SweepInterval; v != "" {
		args = append(args, flag("cluster.sweep.interval", v))
	}

	if v := c.ApplyTimeout; v != "" {
		args = append(args, flag("cluster.apply.timeout", v))
	}

	args = append(args, raftArgs(c.Raft)...)

	if c.SecretRef != nil && c.SecretRef.Name != "" || c.SecretRef == nil {
		// Secrets are always present: supplied or generated.
		args = append(args,
			flag("cluster.gossip.secret", ref(EnvGossipSecret)),
			flag("cluster.secret", ref(EnvClusterSecret)),
		)
	}

	if c.TLS != nil && c.TLS.SecretRef != nil {
		args = append(args,
			flag("cluster.tls.cert", path.Join(clusterTLSMountPath, keyOr(c.TLS.SecretRef.CertKey, "tls.crt"))),
			flag("cluster.tls.key", path.Join(clusterTLSMountPath, keyOr(c.TLS.SecretRef.KeyKey, "tls.key"))),
			flag("cluster.tls.ca", path.Join(clusterTLSMountPath, keyOr(c.TLS.SecretRef.CAKey, "ca.crt"))),
		)
	}

	return append(args, c.ExtraArgs...)
}

func raftArgs(raft plainqv1alpha1.RaftSpec) []string {
	var args []string

	if v := raft.HeartbeatTimeout; v != "" {
		args = append(args, flag("cluster.raft.heartbeat.timeout", v))
	}

	if v := raft.ElectionTimeout; v != "" {
		args = append(args, flag("cluster.raft.election.timeout", v))
	}

	if v := raft.LeaderLeaseTimeout; v != "" {
		args = append(args, flag("cluster.raft.leader-lease.timeout", v))
	}

	if v := raft.CommitTimeout; v != "" {
		args = append(args, flag("cluster.raft.commit.timeout", v))
	}

	if v := raft.SnapshotInterval; v != "" {
		args = append(args, flag("cluster.raft.snapshot.interval", v))
	}

	if v := raft.SnapshotThreshold; v > 0 {
		args = append(args, flag("cluster.raft.snapshot.threshold", strconv.FormatInt(v, 10)))
	}

	if v := raft.TrailingLogs; v > 0 {
		args = append(args, flag("cluster.raft.trailing-logs", strconv.FormatInt(v, 10)))
	}

	return args
}

// DiscoverySpec renders the peer discovery spec string.
//
// The Kubernetes provider is the default because it sees pods that are not
// ready yet — and no PlainQ pod is ready until it has joined a cluster, which
// it cannot do without seeing its peers. DNS discovery avoids the RBAC grant
// but only resolves ready endpoints, so it suits adding nodes to a cluster
// that already exists rather than forming one.
func DiscoverySpec(pq *plainqv1alpha1.PlainQ) string {
	c := pq.Spec.Cluster
	names := NamesFor(pq)

	if c.DiscoverySpec != "" {
		return c.DiscoverySpec
	}

	if c.Discovery == plainqv1alpha1.DiscoveryDNS {
		return fmt.Sprintf("dns://%s.%s.svc.cluster.local?port=%d",
			names.Headless(), ref(EnvNamespace), c.GossipPort)
	}

	selector := fmt.Sprintf("%s=%s,%s=%s", LabelName, AppName, LabelInstance, pq.Name)

	return fmt.Sprintf("kubernetes://?namespace=%s&selector=%s&port=%d",
		ref(EnvNamespace), url.QueryEscape(selector), c.GossipPort)
}

// PodEnv builds the environment for the server container: the secret-sourced
// values the $(VAR) references above consume, plus any user-supplied entries.
func PodEnv(pq *plainqv1alpha1.PlainQ, refs SecretRefs) []corev1.EnvVar {
	spec := pq.Spec

	var env []corev1.EnvVar

	if plainqv1alpha1.BoolValue(spec.Auth.Enabled, true) {
		env = append(env, secretEnv(EnvJWTSecret, refs.JWTSecretName, refs.JWTSecretKey))
	}

	if spec.Storage.Driver == plainqv1alpha1.StoragePostgres && spec.Storage.Postgres.DSNSecretRef != nil {
		env = append(env, secretEnv(EnvPostgresDSN,
			spec.Storage.Postgres.DSNSecretRef.Name, spec.Storage.Postgres.DSNSecretRef.Key))
	}

	if spec.Cluster.Enabled {
		env = append(env,
			// The node id must be stable across restarts — the consensus log
			// is keyed on it — and unique in the cluster. A StatefulSet pod
			// name is both.
			fieldEnv(EnvNodeID, "metadata.name"),
			// Peers dial this pod by IP: it binds 0.0.0.0 and advertises this.
			fieldEnv(EnvPodIP, "status.podIP"),
			fieldEnv(EnvNamespace, "metadata.namespace"),
			secretEnv(EnvGossipSecret, refs.ClusterSecretName, refs.GossipSecretKey),
			secretEnv(EnvClusterSecret, refs.ClusterSecretName, refs.ClusterSecretKey),
		)
	}

	return append(env, spec.Pod.Env...)
}

// SecretRefs names the Secrets a rendered pod reads from. The controller
// resolves user-supplied references and generated names into this before
// rendering, so render itself has no opinion about which is which.
type SecretRefs struct {
	JWTSecretName string
	JWTSecretKey  string

	ClusterSecretName string
	GossipSecretKey   string
	ClusterSecretKey  string
}

// clusterTLSMountPath is where cluster TLS material is mounted.
const clusterTLSMountPath = "/etc/plainq/cluster-tls"

func flag(name, value string) string { return "-" + name + "=" + value }

func ref(envVar string) string { return "$(" + envVar + ")" }

func boolString(v bool) string {
	if v {
		return "true"
	}

	return "false"
}

func keyOr(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func secretEnv(name, secretName, key string) corev1.EnvVar {
	return corev1.EnvVar{
		Name: name,
		ValueFrom: &corev1.EnvVarSource{
			SecretKeyRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: secretName},
				Key:                  key,
			},
		},
	}
}

func fieldEnv(name, fieldPath string) corev1.EnvVar {
	return corev1.EnvVar{
		Name: name,
		ValueFrom: &corev1.EnvVarSource{
			FieldRef: &corev1.ObjectFieldSelector{FieldPath: fieldPath},
		},
	}
}

// sortStrings orders a small slice in place. Rendered args must be stable, or
// every reconcile looks like a change.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
