package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// StorageDriver selects the backend PlainQ stores queues in.
//
// +kubebuilder:validation:Enum=sqlite;postgres
type StorageDriver string

const (
	// StorageSQLite is the embedded single-file backend. It is the default,
	// and the only one cluster mode supports.
	StorageSQLite StorageDriver = "sqlite"

	// StoragePostgres is a shared backend several replicas can talk to.
	StoragePostgres StorageDriver = "postgres"
)

// DiscoveryMode selects how cluster nodes find each other.
//
// +kubebuilder:validation:Enum=kubernetes;dns;custom
type DiscoveryMode string

const (
	// DiscoveryKubernetes queries the API for pods carrying this instance's
	// labels. It sees pods that are not ready yet, which is what a cluster
	// forming for the first time needs.
	DiscoveryKubernetes DiscoveryMode = "kubernetes"

	// DiscoveryDNS resolves the headless Service. It needs no RBAC but only
	// sees ready endpoints, so it suits joining an existing cluster.
	DiscoveryDNS DiscoveryMode = "dns"

	// DiscoveryCustom uses the verbatim spec string in DiscoverySpec.
	DiscoveryCustom DiscoveryMode = "custom"
)

// Consistency selects where reads are served in a cluster.
//
// +kubebuilder:validation:Enum=local;strong
type Consistency string

const (
	// ConsistencyLocal serves reads from the local node. Fast, may lag by
	// milliseconds.
	ConsistencyLocal Consistency = "local"

	// ConsistencyStrong serves reads from the leader. Linearizable.
	ConsistencyStrong Consistency = "strong"
)

// UpdateStrategyType selects how pods are replaced on a spec change.
//
// +kubebuilder:validation:Enum=RollingUpdate;OnDelete
type UpdateStrategyType string

const (
	UpdateRollingUpdate UpdateStrategyType = "RollingUpdate"
	UpdateOnDelete      UpdateStrategyType = "OnDelete"
)

// PlainQPhase is a coarse, human-facing summary of status.
//
// +kubebuilder:validation:Enum=Pending;Provisioning;Running;Degraded;Restoring;Deleting
type PlainQPhase string

const (
	PhasePending      PlainQPhase = "Pending"
	PhaseProvisioning PlainQPhase = "Provisioning"
	PhaseRunning      PlainQPhase = "Running"
	PhaseDegraded     PlainQPhase = "Degraded"
	PhaseRestoring    PlainQPhase = "Restoring"
	PhaseDeleting     PlainQPhase = "Deleting"
)

// PlainQSpec is the desired state of a PlainQ server. Every field maps onto
// one or more `plainq serve` flags; anything not modeled is reachable
// through ExtraArgs.
type PlainQSpec struct {
	// Version selects the server image tag when Image.Tag is empty.
	//
	// +optional
	Version string `json:"version,omitempty"`

	// Image describes the container image.
	//
	// +optional
	Image ImageSpec `json:"image,omitempty"`

	// Replicas is the number of server pods. It is ignored when clustering
	// is enabled, where Cluster.Replicas governs, and forced to 1 for the
	// sqlite driver, which is single-writer.
	//
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Storage selects and configures the backend.
	//
	// +optional
	Storage StorageSpec `json:"storage,omitempty"`

	// Listeners configures the gRPC and HTTP ports.
	//
	// +optional
	Listeners ListenersSpec `json:"listeners,omitempty"`

	// Auth configures JWT authentication.
	//
	// +optional
	Auth AuthSpec `json:"auth,omitempty"`

	// Cluster configures Raft clustering. Off by default: a single PlainQ is
	// a complete PlainQ.
	//
	// +optional
	Cluster ClusterSpec `json:"cluster,omitempty"`

	// Telemetry configures the built-in metrics subsystem.
	//
	// +optional
	Telemetry TelemetrySpec `json:"telemetry,omitempty"`

	// Observability configures health, metrics and Prometheus integration.
	//
	// +optional
	Observability ObservabilitySpec `json:"observability,omitempty"`

	// Logging configures server logs.
	//
	// +optional
	Logging LoggingSpec `json:"logging,omitempty"`

	// Server holds miscellaneous server toggles.
	//
	// +optional
	Server ServerSpec `json:"server,omitempty"`

	// Bootstrap creates the first admin account without a browser.
	//
	// +optional
	Bootstrap BootstrapSpec `json:"bootstrap,omitempty"`

	// Networking configures Services, Ingress, NetworkPolicy and the
	// cutover alias.
	//
	// +optional
	Networking NetworkingSpec `json:"networking,omitempty"`

	// Pod carries the standard pod plumbing applied to every workload.
	//
	// +optional
	Pod PodSpec `json:"pod,omitempty"`

	// Autoscaling renders a HorizontalPodAutoscaler. Postgres driver only:
	// sqlite is single-writer and pinned to one replica.
	//
	// +optional
	Autoscaling AutoscalingSpec `json:"autoscaling,omitempty"`

	// UpdateStrategy governs how pods are replaced.
	//
	// +optional
	UpdateStrategy UpdateStrategySpec `json:"updateStrategy,omitempty"`

	// ExtraArgs are appended verbatim to the serve command. The escape hatch
	// for flags this API does not model.
	//
	// +optional
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

// ImageSpec describes the container image.
type ImageSpec struct {
	// Repository holding the server image.
	//
	// +kubebuilder:default="ghcr.io/marsolab/plainq"
	// +optional
	Repository string `json:"repository,omitempty"`

	// Tag overrides Version.
	//
	// +optional
	Tag string `json:"tag,omitempty"`

	// PullPolicy for the image.
	//
	// +kubebuilder:default=IfNotPresent
	// +optional
	PullPolicy corev1.PullPolicy `json:"pullPolicy,omitempty"`

	// PullSecrets for private registries.
	//
	// +optional
	PullSecrets []corev1.LocalObjectReference `json:"pullSecrets,omitempty"`
}

// StorageSpec selects and configures the backend.
type StorageSpec struct {
	// Driver is sqlite or postgres. Immutable: changing it would abandon the
	// data without migrating it.
	//
	// +kubebuilder:default=sqlite
	// +optional
	Driver StorageDriver `json:"driver,omitempty"`

	// SQLite configures the embedded backend.
	//
	// +optional
	SQLite SQLiteSpec `json:"sqlite,omitempty"`

	// Postgres configures the shared backend.
	//
	// +optional
	Postgres PostgresSpec `json:"postgres,omitempty"`

	// GC configures the eviction sweep.
	//
	// +optional
	GC GCSpec `json:"gc,omitempty"`

	// Log enables storage-engine logging.
	//
	// +optional
	Log bool `json:"log,omitempty"`
}

// SQLiteSpec configures the embedded backend.
type SQLiteSpec struct {
	// Path to the database file inside the container. Its parent directory
	// is the mount point for the data volume.
	//
	// +kubebuilder:default="/data/plainq.db"
	// +optional
	Path string `json:"path,omitempty"`

	// JournalMode for SQLite. Cluster mode requires wal and sets it anyway.
	//
	// +optional
	JournalMode string `json:"journalMode,omitempty"`

	// AccessMode for SQLite.
	//
	// +optional
	AccessMode string `json:"accessMode,omitempty"`

	// Persistence configures the data volume.
	//
	// +optional
	Persistence PersistenceSpec `json:"persistence,omitempty"`
}

// PersistenceSpec configures the data volume.
type PersistenceSpec struct {
	// Enabled provisions a PersistentVolumeClaim. When false the data
	// directory is an emptyDir and the queue does not survive a restart.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Size of the volume. Immutable downward: PVCs do not shrink.
	//
	// +kubebuilder:default="8Gi"
	// +optional
	Size string `json:"size,omitempty"`

	// StorageClassName selects the class. Empty uses the cluster default.
	//
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// AccessModes for the claim. SQLite needs a single writer.
	//
	// +optional
	AccessModes []corev1.PersistentVolumeAccessMode `json:"accessModes,omitempty"`

	// ExistingClaim adopts a volume instead of creating one. This is the
	// migration path from the Helm chart.
	//
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// Annotations added to the claim.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// PostgresSpec configures the shared backend.
type PostgresSpec struct {
	// DSNSecretRef holds the connection string. The operator never accepts a
	// DSN inline: it would end up in the object and in every audit log.
	//
	// +optional
	DSNSecretRef *SecretKeyReference `json:"dsnSecretRef,omitempty"`
}

// GCSpec configures the eviction sweep.
type GCSpec struct {
	// Timeout between sweeps. Empty uses the server default of about 30m.
	//
	// +optional
	Timeout string `json:"timeout,omitempty"`
}

// ListenersSpec configures the two listeners.
type ListenersSpec struct {
	// GRPC is the queue API listener.
	//
	// +optional
	GRPC GRPCListenerSpec `json:"grpc,omitempty"`

	// HTTP serves Houston, the REST API, health and metrics.
	//
	// +optional
	HTTP HTTPListenerSpec `json:"http,omitempty"`
}

// GRPCListenerSpec configures the gRPC listener.
type GRPCListenerSpec struct {
	// Port for the gRPC queue API.
	//
	// +kubebuilder:default=8080
	// +optional
	Port int32 `json:"port,omitempty"`
}

// HTTPListenerSpec configures the HTTP listener.
type HTTPListenerSpec struct {
	// Port for the HTTP surface.
	//
	// +kubebuilder:default=8081
	// +optional
	Port int32 `json:"port,omitempty"`

	// ReadTimeout for HTTP requests. Empty or 0s means none.
	//
	// +optional
	ReadTimeout string `json:"readTimeout,omitempty"`

	// ReadHeaderTimeout for HTTP requests.
	//
	// +optional
	ReadHeaderTimeout string `json:"readHeaderTimeout,omitempty"`

	// WriteTimeout for HTTP responses.
	//
	// +optional
	WriteTimeout string `json:"writeTimeout,omitempty"`

	// IdleTimeout for keep-alive connections.
	//
	// +optional
	IdleTimeout string `json:"idleTimeout,omitempty"`
}

// AuthSpec configures JWT authentication.
type AuthSpec struct {
	// Enabled turns on JWT auth. On by default.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// JWTSecretRef holds the HMAC signing secret. When empty the operator
	// generates one into a Secret it owns.
	//
	// +optional
	JWTSecretRef *SecretKeyReference `json:"jwtSecretRef,omitempty"`

	// AccessTokenTTL is the access-token lifetime.
	//
	// +kubebuilder:default="60m"
	// +optional
	AccessTokenTTL string `json:"accessTokenTTL,omitempty"`

	// RefreshTokenTTL is the refresh-token lifetime.
	//
	// +kubebuilder:default="720h"
	// +optional
	RefreshTokenTTL string `json:"refreshTokenTTL,omitempty"`

	// Registration allows users to sign themselves up.
	//
	// Note: this also gates the only account-creation route the server has,
	// so a PlainQAccount that is not the bootstrap admin needs it on. See
	// the design's server-side gaps.
	//
	// +kubebuilder:default=true
	// +optional
	Registration *bool `json:"registration,omitempty"`

	// EmailVerification requires users to verify their address.
	//
	// +kubebuilder:default=true
	// +optional
	EmailVerification *bool `json:"emailVerification,omitempty"`
}

// ClusterSpec configures Raft clustering.
type ClusterSpec struct {
	// Enabled runs this instance as a cluster. Immutable: turning it on or
	// off changes the storage layout and the failure modes at once.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Replicas is the node count. Use an odd number: a cluster of 2N
	// tolerates the same N-1 failures as one of 2N-1.
	//
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=1
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// ClusterPort carries Raft and internal peer RPC, muxed.
	//
	// +kubebuilder:default=8082
	// +optional
	ClusterPort int32 `json:"clusterPort,omitempty"`

	// GossipPort carries membership over TCP and UDP.
	//
	// +kubebuilder:default=8083
	// +optional
	GossipPort int32 `json:"gossipPort,omitempty"`

	// Discovery selects how nodes find each other.
	//
	// +kubebuilder:default=kubernetes
	// +optional
	Discovery DiscoveryMode `json:"discovery,omitempty"`

	// DiscoverySpec replaces the generated spec string entirely. Required
	// when Discovery is custom.
	//
	// +optional
	DiscoverySpec string `json:"discoverySpec,omitempty"`

	// DiscoveryInterval is how often discovery re-runs.
	//
	// +kubebuilder:default="15s"
	// +optional
	DiscoveryInterval string `json:"discoveryInterval,omitempty"`

	// Consistency selects where reads are served.
	//
	// +kubebuilder:default=local
	// +optional
	Consistency Consistency `json:"consistency,omitempty"`

	// NonVoter replicates the log without voting or counting toward quorum.
	//
	// +optional
	NonVoter bool `json:"nonVoter,omitempty"`

	// BootstrapExpect waits for N nodes before forming a cluster. Defaults
	// to Replicas.
	//
	// +optional
	BootstrapExpect int32 `json:"bootstrapExpect,omitempty"`

	// AutoRemove lets the leader remove long-unreachable members. Off by
	// default: in Kubernetes a rescheduled pod looks exactly like a failed
	// one, and removing a member changes quorum.
	//
	// +optional
	AutoRemove bool `json:"autoRemove,omitempty"`

	// RemoveTimeout is how long unreachable must last before removal.
	//
	// +kubebuilder:default="5m"
	// +optional
	RemoveTimeout string `json:"removeTimeout,omitempty"`

	// ReconcileInterval is how often the leader reconciles gossip against
	// the configuration.
	//
	// +kubebuilder:default="30s"
	// +optional
	ReconcileInterval string `json:"reconcileInterval,omitempty"`

	// SweepInterval is how often the leader proposes queue eviction.
	//
	// +kubebuilder:default="5m"
	// +optional
	SweepInterval string `json:"sweepInterval,omitempty"`

	// ApplyTimeout is how long a replicated write may take.
	//
	// +kubebuilder:default="15s"
	// +optional
	ApplyTimeout string `json:"applyTimeout,omitempty"`

	// FormationTimeout bounds how long the operator waits for a cluster to
	// form before saying so in an event.
	//
	// +kubebuilder:default="5m"
	// +optional
	FormationTimeout string `json:"formationTimeout,omitempty"`

	// SecretRef holds the gossip encryption key and the peer-RPC secret.
	// When empty the operator generates both.
	//
	// +optional
	SecretRef *ClusterSecretReference `json:"secretRef,omitempty"`

	// DataDir holds the consensus log and snapshots.
	//
	// +kubebuilder:default="/data/cluster"
	// +optional
	DataDir string `json:"dataDir,omitempty"`

	// Raft tunes the consensus engine. Empty fields use engine defaults.
	//
	// +optional
	Raft RaftSpec `json:"raft,omitempty"`

	// TLS configures mutually authenticated cluster traffic.
	//
	// +optional
	TLS *ClusterTLSSpec `json:"tls,omitempty"`

	// PodDisruptionBudget renders a PDB derived from quorum.
	//
	// +optional
	PodDisruptionBudget PDBSpec `json:"podDisruptionBudget,omitempty"`

	// ReclaimVolumes decides what happens to a drained node's volume.
	// Retain by default: a volume that still holds a replica is not
	// garbage.
	//
	// +kubebuilder:default=Retain
	// +optional
	ReclaimVolumes DeletionPolicy `json:"reclaimVolumes,omitempty"`

	// ExtraArgs are extra -cluster.* flags.
	//
	// +optional
	ExtraArgs []string `json:"extraArgs,omitempty"`
}

// ClusterSecretReference locates the two cluster secrets.
type ClusterSecretReference struct {
	// Name of the Secret.
	//
	// +optional
	Name string `json:"name,omitempty"`

	// GossipKey holds the base64 gossip encryption key.
	//
	// +kubebuilder:default="gossip-secret"
	// +optional
	GossipKey string `json:"gossipKey,omitempty"`

	// SecretKey holds the peer-RPC shared secret.
	//
	// +kubebuilder:default="cluster-secret"
	// +optional
	SecretKey string `json:"secretKey,omitempty"`
}

// RaftSpec tunes the consensus engine. Widen these for a cluster spread
// across availability zones, where a 1s heartbeat is a false positive
// waiting to happen.
type RaftSpec struct {
	// HeartbeatTimeout is the follower wait before standing for election.
	//
	// +optional
	HeartbeatTimeout string `json:"heartbeatTimeout,omitempty"`

	// ElectionTimeout is the candidate wait for votes.
	//
	// +optional
	ElectionTimeout string `json:"electionTimeout,omitempty"`

	// LeaderLeaseTimeout is the leader wait before stepping down.
	//
	// +optional
	LeaderLeaseTimeout string `json:"leaderLeaseTimeout,omitempty"`

	// CommitTimeout is the leader batching window.
	//
	// +optional
	CommitTimeout string `json:"commitTimeout,omitempty"`

	// SnapshotInterval is how often the log is compacted.
	//
	// +optional
	SnapshotInterval string `json:"snapshotInterval,omitempty"`

	// SnapshotThreshold is the entry count that triggers a snapshot.
	//
	// +optional
	SnapshotThreshold int64 `json:"snapshotThreshold,omitempty"`

	// TrailingLogs are entries kept after a snapshot for lagging followers.
	//
	// +optional
	TrailingLogs int64 `json:"trailingLogs,omitempty"`
}

// ClusterTLSSpec configures mutually authenticated cluster traffic.
type ClusterTLSSpec struct {
	// SecretRef holds the certificate, key and CA.
	//
	// +optional
	SecretRef *ClusterTLSSecretReference `json:"secretRef,omitempty"`
}

// ClusterTLSSecretReference locates cluster TLS material.
type ClusterTLSSecretReference struct {
	// Name of the Secret.
	Name string `json:"name"`

	// CertKey holds the certificate.
	//
	// +kubebuilder:default="tls.crt"
	// +optional
	CertKey string `json:"certKey,omitempty"`

	// KeyKey holds the private key.
	//
	// +kubebuilder:default="tls.key"
	// +optional
	KeyKey string `json:"keyKey,omitempty"`

	// CAKey holds the issuing CA.
	//
	// +kubebuilder:default="ca.crt"
	// +optional
	CAKey string `json:"caKey,omitempty"`
}

// PDBSpec configures a PodDisruptionBudget.
type PDBSpec struct {
	// Enabled renders the budget.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`
}

// TelemetrySpec configures the built-in metrics subsystem.
type TelemetrySpec struct {
	// Enabled turns on telemetry.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Provider selects the telemetry backend.
	//
	// +kubebuilder:default=sqlite
	// +optional
	Provider string `json:"provider,omitempty"`

	// CollectionInterval between metric collections.
	//
	// +kubebuilder:default="10s"
	// +optional
	CollectionInterval string `json:"collectionInterval,omitempty"`

	// GCInterval between telemetry sweeps.
	//
	// +kubebuilder:default="10m"
	// +optional
	GCInterval string `json:"gcInterval,omitempty"`

	// RetentionPeriod for telemetry samples.
	//
	// +kubebuilder:default="336h"
	// +optional
	RetentionPeriod string `json:"retentionPeriod,omitempty"`

	// PrometheusBaseURL points at an external Prometheus API.
	//
	// +optional
	PrometheusBaseURL string `json:"prometheusBaseURL,omitempty"`

	// Log enables telemetry activity logging.
	//
	// +optional
	Log bool `json:"log,omitempty"`
}

// ObservabilitySpec configures health, metrics and Prometheus integration.
type ObservabilitySpec struct {
	// Health configures the health endpoint.
	//
	// +optional
	Health EndpointSpec `json:"health,omitempty"`

	// Metrics configures the Prometheus endpoint.
	//
	// +optional
	Metrics EndpointSpec `json:"metrics,omitempty"`

	// ServiceMonitor renders a Prometheus Operator ServiceMonitor.
	//
	// +optional
	ServiceMonitor ServiceMonitorSpec `json:"serviceMonitor,omitempty"`

	// PrometheusRule renders the bundled alert set.
	//
	// +optional
	PrometheusRule PrometheusRuleSpec `json:"prometheusRule,omitempty"`

	// GrafanaDashboard renders a dashboard ConfigMap.
	//
	// +optional
	GrafanaDashboard GrafanaDashboardSpec `json:"grafanaDashboard,omitempty"`
}

// EndpointSpec configures one of the server's utility endpoints.
type EndpointSpec struct {
	// Enabled turns the endpoint on.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Route is the HTTP path.
	//
	// +optional
	Route string `json:"route,omitempty"`

	// Logs enables access logging for the endpoint.
	//
	// +optional
	Logs bool `json:"logs,omitempty"`

	// Metrics enables self-metrics for the endpoint.
	//
	// +optional
	Metrics bool `json:"metrics,omitempty"`

	// Reporter selects the health reporter format. Health only.
	//
	// +optional
	Reporter string `json:"reporter,omitempty"`
}

// ServiceMonitorSpec configures Prometheus Operator scraping.
type ServiceMonitorSpec struct {
	// Enabled renders the ServiceMonitor.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Interval between scrapes.
	//
	// +kubebuilder:default="30s"
	// +optional
	Interval string `json:"interval,omitempty"`

	// ScrapeTimeout per scrape.
	//
	// +kubebuilder:default="10s"
	// +optional
	ScrapeTimeout string `json:"scrapeTimeout,omitempty"`

	// Labels for the ServiceMonitor. Many operator installs need a release
	// label to select it.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations for the ServiceMonitor.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Relabelings applied before scraping.
	//
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	Relabelings []RelabelConfig `json:"relabelings,omitempty"`

	// MetricRelabelings applied to scraped samples.
	//
	// +optional
	// +kubebuilder:pruning:PreserveUnknownFields
	MetricRelabelings []RelabelConfig `json:"metricRelabelings,omitempty"`
}

// RelabelConfig is the subset of Prometheus relabeling the operator renders.
// It is modeled here rather than imported so the operator does not depend on
// the Prometheus Operator's Go module to compile.
type RelabelConfig struct {
	// SourceLabels feeding the rule.
	//
	// +optional
	SourceLabels []string `json:"sourceLabels,omitempty"`

	// Separator between concatenated source label values.
	//
	// +optional
	Separator string `json:"separator,omitempty"`

	// TargetLabel written by replace actions.
	//
	// +optional
	TargetLabel string `json:"targetLabel,omitempty"`

	// Regex matched against the concatenated source labels.
	//
	// +optional
	Regex string `json:"regex,omitempty"`

	// Modulus for hashmod.
	//
	// +optional
	Modulus uint64 `json:"modulus,omitempty"`

	// Replacement value.
	//
	// +optional
	Replacement string `json:"replacement,omitempty"`

	// Action to take.
	//
	// +optional
	Action string `json:"action,omitempty"`
}

// PrometheusRuleSpec configures the bundled alert set.
type PrometheusRuleSpec struct {
	// Enabled renders the PrometheusRule.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Labels for the PrometheusRule.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// GrafanaDashboardSpec configures the dashboard ConfigMap.
type GrafanaDashboardSpec struct {
	// Enabled renders the ConfigMap.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// Label the Grafana sidecar selects on.
	//
	// +kubebuilder:default="grafana_dashboard"
	// +optional
	Label string `json:"label,omitempty"`
}

// LoggingSpec configures server logs.
type LoggingSpec struct {
	// Enabled turns on logging.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// Level is debug, info, warning or error.
	//
	// +kubebuilder:validation:Enum=debug;info;warning;error
	// +kubebuilder:default=info
	// +optional
	Level string `json:"level,omitempty"`

	// AccessLogs enables HTTP access logging.
	//
	// +kubebuilder:default=true
	// +optional
	AccessLogs *bool `json:"accessLogs,omitempty"`
}

// ServerSpec holds miscellaneous server toggles.
type ServerSpec struct {
	// CORS enables cross-origin requests for Houston's API routes.
	//
	// +kubebuilder:default=true
	// +optional
	CORS *bool `json:"cors,omitempty"`

	// Profiler exposes the profiling endpoint.
	//
	// +optional
	Profiler bool `json:"profiler,omitempty"`
}

// BootstrapSpec creates the first admin account without a browser. This is
// what makes an unattended GitOps deployment possible to finish.
type BootstrapSpec struct {
	// Enabled creates the account.
	//
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// AdminSecretRef holds the admin email and password. The operator
	// generates a password into this Secret when it does not exist.
	//
	// +optional
	AdminSecretRef *CredentialsSecretReference `json:"adminSecretRef,omitempty"`
}

// NetworkingSpec configures Services, Ingress, NetworkPolicy and the alias.
type NetworkingSpec struct {
	// Service configures the instance's own Service.
	//
	// +optional
	Service ServiceSpec `json:"service,omitempty"`

	// Alias is a stable name clients connect to, decoupled from this
	// instance's Service. Exactly one PlainQ may hold a given alias at a
	// time, which makes a cutover a single atomic, reversible edit.
	//
	// Hand-editing a Service selector does not work here: Services are owned
	// by their PlainQ and server-side apply reverts the change on the next
	// reconcile.
	//
	// +optional
	Alias AliasSpec `json:"alias,omitempty"`

	// Ingress exposes the instance outside the cluster.
	//
	// +optional
	Ingress IngressSpec `json:"ingress,omitempty"`

	// NetworkPolicy restricts who can reach the listeners. Given that the
	// gRPC surface carries no authentication today, this is the control that
	// actually protects the queue API.
	//
	// +optional
	NetworkPolicy NetworkPolicySpec `json:"networkPolicy,omitempty"`
}

// ServiceSpec configures the instance Service.
type ServiceSpec struct {
	// Type of Service.
	//
	// +kubebuilder:default=ClusterIP
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`

	// Annotations for the Service.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels for the Service.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// AliasSpec names a Service that follows whichever instance claims it.
type AliasSpec struct {
	// Name of the alias Service. Empty means no alias.
	//
	// +optional
	Name string `json:"name,omitempty"`
}

// IngressSpec exposes the instance outside the cluster.
type IngressSpec struct {
	// Enabled renders the Ingress.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// ClassName selects the IngressClass.
	//
	// +optional
	ClassName string `json:"className,omitempty"`

	// Annotations for the Ingress. gRPC needs a backend-protocol hint on
	// most controllers.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Hosts routed to this instance.
	//
	// +optional
	Hosts []IngressHost `json:"hosts,omitempty"`

	// TLS configuration. gRPC over Ingress effectively requires it.
	//
	// +optional
	TLS []IngressTLS `json:"tls,omitempty"`
}

// IngressHost is one host and its paths.
type IngressHost struct {
	// Host name.
	Host string `json:"host"`

	// Paths under the host.
	//
	// +optional
	Paths []IngressPath `json:"paths,omitempty"`
}

// IngressPath routes a path to one of the two Service ports.
type IngressPath struct {
	// Path to match.
	//
	// +kubebuilder:default="/"
	// +optional
	Path string `json:"path,omitempty"`

	// PathType for the match.
	//
	// +kubebuilder:default=Prefix
	// +optional
	PathType string `json:"pathType,omitempty"`

	// Port is http or grpc.
	//
	// +kubebuilder:validation:Enum=http;grpc
	// +kubebuilder:default=http
	// +optional
	Port string `json:"port,omitempty"`
}

// IngressTLS is one TLS entry.
type IngressTLS struct {
	// SecretName holding the certificate.
	SecretName string `json:"secretName"`

	// Hosts covered by the certificate.
	//
	// +optional
	Hosts []string `json:"hosts,omitempty"`
}

// NetworkPolicySpec restricts access to the listeners.
type NetworkPolicySpec struct {
	// Enabled renders a default-deny policy with the allowances below.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// AllowFrom lists the peers permitted to reach the gRPC and HTTP ports.
	//
	// +optional
	AllowFrom []NetworkPolicyPeer `json:"allowFrom,omitempty"`
}

// NetworkPolicyPeer selects pods or namespaces allowed to connect.
type NetworkPolicyPeer struct {
	// PodSelector selects pods, in the policy's namespace unless
	// NamespaceSelector is also set.
	//
	// +optional
	PodSelector *metav1.LabelSelector `json:"podSelector,omitempty"`

	// NamespaceSelector selects namespaces.
	//
	// +optional
	NamespaceSelector *metav1.LabelSelector `json:"namespaceSelector,omitempty"`
}

// PodSpec carries standard pod plumbing.
type PodSpec struct {
	// Resources for the server container.
	//
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// NodeSelector for scheduling.
	//
	// +optional
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Tolerations for scheduling.
	//
	// +optional
	Tolerations []corev1.Toleration `json:"tolerations,omitempty"`

	// Affinity rules.
	//
	// +optional
	Affinity *corev1.Affinity `json:"affinity,omitempty"`

	// TopologySpreadConstraints spread nodes across failure domains.
	//
	// +optional
	TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`

	// Annotations added to every pod.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels added to every pod.
	//
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// SecurityContext at pod level. Defaulted to a hardened profile.
	//
	// +optional
	SecurityContext *corev1.PodSecurityContext `json:"securityContext,omitempty"`

	// ContainerSecurityContext at container level. Defaulted to a hardened
	// profile matching the distroless nonroot image.
	//
	// +optional
	ContainerSecurityContext *corev1.SecurityContext `json:"containerSecurityContext,omitempty"`

	// PriorityClassName for scheduling.
	//
	// +optional
	PriorityClassName string `json:"priorityClassName,omitempty"`

	// TerminationGracePeriodSeconds before SIGKILL.
	//
	// +kubebuilder:default=60
	// +optional
	TerminationGracePeriodSeconds *int64 `json:"terminationGracePeriodSeconds,omitempty"`

	// ServiceAccount configuration.
	//
	// +optional
	ServiceAccount ServiceAccountSpec `json:"serviceAccount,omitempty"`

	// Env adds environment variables to the server container.
	//
	// +optional
	Env []corev1.EnvVar `json:"env,omitempty"`

	// EnvFrom adds environment sources.
	//
	// +optional
	EnvFrom []corev1.EnvFromSource `json:"envFrom,omitempty"`

	// ExtraVolumes added to the pod.
	//
	// +optional
	ExtraVolumes []corev1.Volume `json:"extraVolumes,omitempty"`

	// ExtraVolumeMounts added to the server container.
	//
	// +optional
	ExtraVolumeMounts []corev1.VolumeMount `json:"extraVolumeMounts,omitempty"`

	// Sidecars added to the pod.
	//
	// +optional
	Sidecars []corev1.Container `json:"sidecars,omitempty"`

	// InitContainers added to the pod.
	//
	// +optional
	InitContainers []corev1.Container `json:"initContainers,omitempty"`

	// LivenessProbe overrides the default.
	//
	// +optional
	LivenessProbe *corev1.Probe `json:"livenessProbe,omitempty"`

	// ReadinessProbe overrides the default.
	//
	// +optional
	ReadinessProbe *corev1.Probe `json:"readinessProbe,omitempty"`

	// StartupProbe for slow-starting instances.
	//
	// +optional
	StartupProbe *corev1.Probe `json:"startupProbe,omitempty"`
}

// ServiceAccountSpec configures the instance ServiceAccount.
type ServiceAccountSpec struct {
	// Create the ServiceAccount.
	//
	// +kubebuilder:default=true
	// +optional
	Create *bool `json:"create,omitempty"`

	// Name of the ServiceAccount. Generated when empty.
	//
	// +optional
	Name string `json:"name,omitempty"`

	// Annotations for IRSA or workload identity.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// AutoscalingSpec renders a HorizontalPodAutoscaler.
type AutoscalingSpec struct {
	// Enabled renders the HPA. Postgres driver only.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// MinReplicas floor.
	//
	// +kubebuilder:default=2
	// +optional
	MinReplicas int32 `json:"minReplicas,omitempty"`

	// MaxReplicas ceiling.
	//
	// +kubebuilder:default=5
	// +optional
	MaxReplicas int32 `json:"maxReplicas,omitempty"`

	// TargetCPUUtilizationPercentage to scale on.
	//
	// +kubebuilder:default=80
	// +optional
	TargetCPUUtilizationPercentage int32 `json:"targetCPUUtilizationPercentage,omitempty"`

	// TargetMemoryUtilizationPercentage to scale on. 0 disables.
	//
	// +optional
	TargetMemoryUtilizationPercentage int32 `json:"targetMemoryUtilizationPercentage,omitempty"`
}

// UpdateStrategySpec governs how pods are replaced.
type UpdateStrategySpec struct {
	// Type of update.
	//
	// +kubebuilder:default=RollingUpdate
	// +optional
	Type UpdateStrategyType `json:"type,omitempty"`

	// QuorumAware drives the roll one pod at a time, waiting for each to
	// rejoin as a voter, and restarts the leader last so the roll costs one
	// election rather than several. Cluster mode only.
	//
	// +kubebuilder:default=true
	// +optional
	QuorumAware *bool `json:"quorumAware,omitempty"`
}

// PlainQStatus is the observed state of a PlainQ server.
type PlainQStatus struct {
	// Phase is a coarse summary for humans.
	//
	// +optional
	Phase PlainQPhase `json:"phase,omitempty"`

	// ObservedGeneration is the spec generation this status reflects.
	//
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ReadyReplicas is the number of ready server pods.
	//
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// Replicas is the number of desired server pods.
	//
	// +optional
	Replicas int32 `json:"replicas,omitempty"`

	// Endpoint is the in-cluster DNS name of the Service.
	//
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// GRPCEndpoint is host:port for the queue API.
	//
	// +optional
	GRPCEndpoint string `json:"grpcEndpoint,omitempty"`

	// HTTPEndpoint is the base URL of the HTTP surface.
	//
	// +optional
	HTTPEndpoint string `json:"httpEndpoint,omitempty"`

	// Version currently deployed.
	//
	// +optional
	Version string `json:"version,omitempty"`

	// Storage describes the backend in use.
	//
	// +optional
	Storage *StorageStatus `json:"storage,omitempty"`

	// Cluster describes consensus state.
	//
	// +optional
	Cluster *ClusterStatus `json:"cluster,omitempty"`

	// Bootstrap describes the first-admin account.
	//
	// +optional
	Bootstrap *BootstrapStatus `json:"bootstrap,omitempty"`

	// LastBackup summarizes the most recent backup of this instance.
	//
	// +optional
	LastBackup *LastBackupStatus `json:"lastBackup,omitempty"`

	// Conditions follow the Kubernetes convention.
	//
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// StorageStatus describes the backend in use.
type StorageStatus struct {
	// Driver in use.
	//
	// +optional
	Driver StorageDriver `json:"driver,omitempty"`

	// PersistentVolumeClaims backing the instance.
	//
	// +optional
	PersistentVolumeClaims []string `json:"persistentVolumeClaims,omitempty"`
}

// ClusterStatus describes consensus state as the operator last saw it.
type ClusterStatus struct {
	// Formed reports whether the cluster has a leader and its voters.
	//
	// +optional
	Formed bool `json:"formed,omitempty"`

	// Leader is the node ID of the current leader.
	//
	// +optional
	Leader string `json:"leader,omitempty"`

	// Voters counted toward quorum.
	//
	// +optional
	Voters int32 `json:"voters,omitempty"`

	// NonVoters replicating without voting.
	//
	// +optional
	NonVoters int32 `json:"nonVoters,omitempty"`

	// Quorum currently required.
	//
	// +optional
	Quorum int32 `json:"quorum,omitempty"`

	// Members merges the consensus configuration with the gossip view.
	//
	// +optional
	Members []ClusterMemberStatus `json:"members,omitempty"`
}

// ClusterMemberStatus is one node as the operator last saw it.
type ClusterMemberStatus struct {
	// ID of the node.
	ID string `json:"id"`

	// Address peers dial for consensus.
	//
	// +optional
	Address string `json:"address,omitempty"`

	// Status from the gossip view.
	//
	// +optional
	Status string `json:"status,omitempty"`

	// Voter reports whether the node counts toward quorum.
	//
	// +optional
	Voter bool `json:"voter,omitempty"`

	// Reachable reports gossip reachability.
	//
	// +optional
	Reachable bool `json:"reachable,omitempty"`
}

// BootstrapStatus describes the first-admin account.
type BootstrapStatus struct {
	// Completed reports that an admin exists.
	//
	// +optional
	Completed bool `json:"completed,omitempty"`

	// AdminSecret names the Secret holding the credentials.
	//
	// +optional
	AdminSecret string `json:"adminSecret,omitempty"`
}

// LastBackupStatus summarizes the most recent backup.
type LastBackupStatus struct {
	// Name of the PlainQBackup.
	//
	// +optional
	Name string `json:"name,omitempty"`

	// Time the backup completed.
	//
	// +optional
	Time *metav1.Time `json:"time,omitempty"`

	// Result of the backup.
	//
	// +optional
	Result string `json:"result,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=pq,categories=plainq
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Version",type=string,JSONPath=`.status.version`
// +kubebuilder:printcolumn:name="Driver",type=string,JSONPath=`.status.storage.driver`
// +kubebuilder:printcolumn:name="Leader",type=string,JSONPath=`.status.cluster.leader`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PlainQ is a PlainQ server: a single node, a Postgres-backed deployment, or
// a Raft cluster.
type PlainQ struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PlainQSpec   `json:"spec,omitempty"`
	Status PlainQStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PlainQList contains a list of PlainQ.
type PlainQList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PlainQ `json:"items"`
}
