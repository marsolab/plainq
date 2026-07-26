package v1alpha1

import corev1 "k8s.io/api/core/v1"

// Default values applied when a field is left empty. They live here rather
// than only in kubebuilder markers so that rendering, the webhook, and tests
// all agree without a running API server to apply CRD defaults.
const (
	DefaultImageRepository = "ghcr.io/marsolab/plainq"
	DefaultGRPCPort        = 8080
	DefaultHTTPPort        = 8081
	DefaultClusterPort     = 8082
	DefaultGossipPort      = 8083
	DefaultSQLitePath      = "/data/plainq.db"
	DefaultClusterDataDir  = "/data/cluster"
	DefaultVolumeSize      = "8Gi"
	DefaultHealthRoute     = "/health"
	DefaultMetricsRoute    = "/metrics"
	DefaultLogLevel        = "info"
	DefaultClusterReplicas = 3

	// nonRootUID matches the distroless nonroot image the server ships on.
	nonRootUID = 65532
)

func boolPtr(v bool) *bool    { return &v }
func int64Ptr(v int64) *int64 { return &v }

// BoolValue dereferences an optional bool, treating nil as fallback. Optional
// booleans are pointers throughout this API so that "unset" and "false" stay
// distinguishable — several of these default to true.
func BoolValue(v *bool, fallback bool) bool {
	if v == nil {
		return fallback
	}

	return *v
}

// ApplyDefaults fills empty fields with their documented defaults. It is
// idempotent, so calling it in the webhook and again at render time is safe.
//
//nolint:cyclop,gocyclo // A defaulting function is a flat list of fallbacks.
func (s *PlainQSpec) ApplyDefaults() {
	if s.Image.Repository == "" {
		s.Image.Repository = DefaultImageRepository
	}

	if s.Image.PullPolicy == "" {
		s.Image.PullPolicy = corev1.PullIfNotPresent
	}

	if s.Replicas == 0 && !s.Cluster.Enabled {
		s.Replicas = 1
	}

	// SQLite is single-writer on one ReadWriteOnce volume. Outside cluster
	// mode, where each node owns its own database, more than one replica is
	// not a scaling decision but a corruption risk.
	if s.Storage.Driver == StorageSQLite && !s.Cluster.Enabled {
		s.Replicas = 1
	}

	s.defaultStorage()
	s.defaultListeners()
	s.defaultAuth()
	s.defaultCluster()
	s.defaultTelemetry()
	s.defaultObservability()
	s.defaultLogging()
	s.defaultPod()
}

func (s *PlainQSpec) defaultStorage() {
	if s.Storage.Driver == "" {
		s.Storage.Driver = StorageSQLite
	}

	if s.Storage.SQLite.Path == "" {
		s.Storage.SQLite.Path = DefaultSQLitePath
	}

	if s.Storage.SQLite.Persistence.Enabled == nil {
		s.Storage.SQLite.Persistence.Enabled = boolPtr(true)
	}

	if s.Storage.SQLite.Persistence.Size == "" {
		s.Storage.SQLite.Persistence.Size = DefaultVolumeSize
	}

	if len(s.Storage.SQLite.Persistence.AccessModes) == 0 {
		s.Storage.SQLite.Persistence.AccessModes = []corev1.PersistentVolumeAccessMode{
			corev1.ReadWriteOnce,
		}
	}
}

func (s *PlainQSpec) defaultListeners() {
	if s.Listeners.GRPC.Port == 0 {
		s.Listeners.GRPC.Port = DefaultGRPCPort
	}

	if s.Listeners.HTTP.Port == 0 {
		s.Listeners.HTTP.Port = DefaultHTTPPort
	}
}

func (s *PlainQSpec) defaultAuth() {
	if s.Auth.Enabled == nil {
		s.Auth.Enabled = boolPtr(true)
	}

	if s.Auth.AccessTokenTTL == "" {
		s.Auth.AccessTokenTTL = "60m"
	}

	if s.Auth.RefreshTokenTTL == "" {
		s.Auth.RefreshTokenTTL = "720h"
	}

	if s.Auth.Registration == nil {
		s.Auth.Registration = boolPtr(true)
	}

	if s.Auth.EmailVerification == nil {
		s.Auth.EmailVerification = boolPtr(true)
	}
}

func (s *PlainQSpec) defaultCluster() {
	if !s.Cluster.Enabled {
		return
	}

	if s.Cluster.Replicas == 0 {
		s.Cluster.Replicas = DefaultClusterReplicas
	}

	if s.Cluster.ClusterPort == 0 {
		s.Cluster.ClusterPort = DefaultClusterPort
	}

	if s.Cluster.GossipPort == 0 {
		s.Cluster.GossipPort = DefaultGossipPort
	}

	if s.Cluster.Discovery == "" {
		s.Cluster.Discovery = DiscoveryKubernetes
	}

	if s.Cluster.Consistency == "" {
		s.Cluster.Consistency = ConsistencyLocal
	}

	if s.Cluster.DataDir == "" {
		s.Cluster.DataDir = DefaultClusterDataDir
	}

	// bootstrap-expect waits for this many nodes to be visible before
	// forming a cluster, which is why pods come up in parallel.
	if s.Cluster.BootstrapExpect == 0 {
		s.Cluster.BootstrapExpect = s.Cluster.Replicas
	}

	if s.Cluster.RemoveTimeout == "" {
		s.Cluster.RemoveTimeout = "5m"
	}

	if s.Cluster.FormationTimeout == "" {
		s.Cluster.FormationTimeout = "5m"
	}

	if s.Cluster.ReclaimVolumes == "" {
		s.Cluster.ReclaimVolumes = DeletionRetain
	}

	if s.Cluster.PodDisruptionBudget.Enabled == nil {
		s.Cluster.PodDisruptionBudget.Enabled = boolPtr(true)
	}

	// Cluster mode requires WAL journal mode, and sets it itself. Recording
	// it here keeps status and rendered args honest about what is in force.
	if s.Storage.SQLite.JournalMode == "" {
		s.Storage.SQLite.JournalMode = "wal"
	}
}

func (s *PlainQSpec) defaultTelemetry() {
	if s.Telemetry.Enabled == nil {
		s.Telemetry.Enabled = boolPtr(true)
	}

	if s.Telemetry.Provider == "" {
		s.Telemetry.Provider = "sqlite"
	}
}

func (s *PlainQSpec) defaultObservability() {
	if s.Observability.Health.Enabled == nil {
		s.Observability.Health.Enabled = boolPtr(true)
	}

	if s.Observability.Health.Route == "" {
		s.Observability.Health.Route = DefaultHealthRoute
	}

	if s.Observability.Metrics.Enabled == nil {
		s.Observability.Metrics.Enabled = boolPtr(true)
	}

	if s.Observability.Metrics.Route == "" {
		s.Observability.Metrics.Route = DefaultMetricsRoute
	}
}

func (s *PlainQSpec) defaultLogging() {
	if s.Logging.Enabled == nil {
		s.Logging.Enabled = boolPtr(true)
	}

	if s.Logging.Level == "" {
		s.Logging.Level = DefaultLogLevel
	}

	if s.Logging.AccessLogs == nil {
		s.Logging.AccessLogs = boolPtr(true)
	}

	if s.Server.CORS == nil {
		s.Server.CORS = boolPtr(true)
	}
}

func (s *PlainQSpec) defaultPod() {
	if s.Pod.ServiceAccount.Create == nil {
		s.Pod.ServiceAccount.Create = boolPtr(true)
	}

	if s.Pod.TerminationGracePeriodSeconds == nil {
		s.Pod.TerminationGracePeriodSeconds = int64Ptr(60)
	}

	if s.UpdateStrategy.Type == "" {
		s.UpdateStrategy.Type = UpdateRollingUpdate
	}

	if s.UpdateStrategy.QuorumAware == nil {
		s.UpdateStrategy.QuorumAware = boolPtr(true)
	}

	if s.Bootstrap.Enabled == nil {
		s.Bootstrap.Enabled = boolPtr(true)
	}

	if s.Pod.SecurityContext == nil {
		uid := int64(nonRootUID)
		s.Pod.SecurityContext = &corev1.PodSecurityContext{
			RunAsNonRoot: boolPtr(true),
			RunAsUser:    &uid,
			RunAsGroup:   &uid,
			// fsGroup makes the mounted volume writable by the nonroot user.
			FSGroup:        &uid,
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		}
	}

	if s.Pod.ContainerSecurityContext == nil {
		uid := int64(nonRootUID)
		s.Pod.ContainerSecurityContext = &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   boolPtr(true),
			RunAsNonRoot:             boolPtr(true),
			RunAsUser:                &uid,
			AllowPrivilegeEscalation: boolPtr(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		}
	}
}

// ImageRef returns the fully qualified image reference.
func (s *PlainQSpec) ImageRef() string {
	tag := s.Image.Tag
	if tag == "" {
		tag = s.Version
	}

	if tag == "" {
		tag = "latest"
	}

	repository := s.Image.Repository
	if repository == "" {
		repository = DefaultImageRepository
	}

	return repository + ":" + tag
}

// DesiredReplicas returns how many server pods the spec asks for.
func (s *PlainQSpec) DesiredReplicas() int32 {
	if s.Cluster.Enabled {
		return s.Cluster.Replicas
	}

	if s.Storage.Driver == StorageSQLite {
		return 1
	}

	return s.Replicas
}

// Quorum returns how many voters a write needs at the given member count.
func Quorum(voters int32) int32 { return voters/2 + 1 }
