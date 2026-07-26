package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// Condition types shared across kinds. The first three follow the Kubernetes
// convention; the rest are kind-specific but named consistently.
const (
	// ConditionReady reports whether the object is serving its purpose.
	ConditionReady = "Ready"

	// ConditionProgressing reports that the operator is actively working
	// toward the desired state.
	ConditionProgressing = "Progressing"

	// ConditionDegraded reports that the object is not in the desired state
	// and the operator cannot get it there on its own.
	ConditionDegraded = "Degraded"

	// ConditionClusterFormed reports that a cluster has a leader and the
	// expected number of voters.
	ConditionClusterFormed = "ClusterFormed"

	// ConditionBootstrapped reports that the first admin account exists.
	ConditionBootstrapped = "Bootstrapped"

	// ConditionSynced reports that the server-side object matches spec.
	ConditionSynced = "Synced"

	// ConditionComplete reports that a one-shot operation finished.
	ConditionComplete = "Complete"

	// ConditionBackupHealthy reports on the freshness of backups.
	ConditionBackupHealthy = "BackupHealthy"

	// ConditionContinuousHealthy reports on continuous replication lag.
	ConditionContinuousHealthy = "ContinuousHealthy"

	// ConditionScheduleHealthy reports on the scheduled backup CronJob.
	ConditionScheduleHealthy = "ScheduleHealthy"
)

// Condition reasons. These are part of the API: users and scripts match on
// them, so they change only with the API version.
const (
	ReasonReconciling           = "Reconciling"
	ReasonAvailable             = "Available"
	ReasonWaitingForDependency  = "WaitingForDependency"
	ReasonImmutableFieldChanged = "ImmutableFieldChanged"
	ReasonServerUnreachable     = "ServerUnreachable"
	ReasonNotBootstrapped       = "NotBootstrapped"
	ReasonRegistrationDisabled  = "RegistrationDisabled"
	ReasonQuorumRisk            = "QuorumRisk"
	ReasonBackupFailed          = "BackupFailed"
	ReasonBackupStale           = "BackupStale"
	ReasonRestoreFailed         = "RestoreFailed"
	ReasonAliasConflict         = "AliasConflict"
)

// DeletionPolicy decides what happens to the server-side resource when the
// Kubernetes object is deleted.
//
// +kubebuilder:validation:Enum=Retain;Delete
type DeletionPolicy string

const (
	// DeletionRetain leaves the resource on the PlainQ server. The default:
	// deleting a Kubernetes object should not silently destroy data.
	DeletionRetain DeletionPolicy = "Retain"

	// DeletionDelete removes the resource from the server too.
	DeletionDelete DeletionPolicy = "Delete"
)

// ServerReference points at the PlainQ instance an object belongs to. Either
// Name (an instance in the same namespace that the operator manages) or
// Endpoint (an instance it does not) must be set.
type ServerReference struct {
	// Name of a PlainQ object in the same namespace.
	//
	// +optional
	Name string `json:"name,omitempty"`

	// Endpoint is the base URL of a PlainQ HTTP listener the operator does
	// not manage, for example http://plainq.other.svc:8081.
	//
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// CredentialsSecretRef holds admin credentials for Endpoint. Ignored when
	// Name is set, because the operator already holds that instance's
	// bootstrap credentials.
	//
	// +optional
	CredentialsSecretRef *CredentialsSecretReference `json:"credentialsSecretRef,omitempty"`
}

// CredentialsSecretReference locates an email/password pair in a Secret.
type CredentialsSecretReference struct {
	// Name of the Secret.
	Name string `json:"name"`

	// EmailKey is the key holding the account email.
	//
	// +kubebuilder:default=email
	// +optional
	EmailKey string `json:"emailKey,omitempty"`

	// PasswordKey is the key holding the account password.
	//
	// +kubebuilder:default=password
	// +optional
	PasswordKey string `json:"passwordKey,omitempty"`
}

// SecretKeyReference locates a single value in a Secret.
type SecretKeyReference struct {
	// Name of the Secret.
	Name string `json:"name"`

	// Key within the Secret.
	Key string `json:"key"`
}

// LocalObjectReference names an object in the same namespace.
type LocalObjectReference struct {
	// Name of the referenced object.
	Name string `json:"name"`
}

// Compression algorithm applied to a backup artifact before upload.
//
// +kubebuilder:validation:Enum=none;gzip;zstd
type Compression string

const (
	CompressionNone Compression = "none"
	CompressionGzip Compression = "gzip"
	CompressionZstd Compression = "zstd"
)

// Extension returns the filename suffix an artifact carries for this
// compression, including the leading dot. It is empty for CompressionNone.
func (c Compression) Extension() string {
	switch c {
	case CompressionGzip:
		return ".gz"
	case CompressionZstd:
		return ".zst"
	default:
		return ""
	}
}

// EncryptionSpec configures at-rest encryption of backup artifacts.
type EncryptionSpec struct {
	// Enabled turns on encryption.
	//
	// +optional
	Enabled bool `json:"enabled,omitempty"`

	// SecretRef holds the age identity used to encrypt and decrypt.
	//
	// +optional
	SecretRef *SecretKeyReference `json:"secretRef,omitempty"`
}

// Destination is where backup artifacts are written. Exactly one of S3 or
// Filesystem must be set; the validating webhook enforces it.
type Destination struct {
	// S3 writes to S3-compatible object storage.
	//
	// +optional
	S3 *S3Destination `json:"s3,omitempty"`

	// Filesystem writes to a PersistentVolume.
	//
	// +optional
	Filesystem *FilesystemDestination `json:"filesystem,omitempty"`
}

// S3Destination describes an S3-compatible bucket. It covers AWS S3, MinIO,
// Cloudflare R2, Ceph RGW and Wasabi.
type S3Destination struct {
	// Endpoint is the S3 API endpoint. Empty means the AWS endpoint derived
	// from Region.
	//
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// Region of the bucket.
	//
	// +optional
	Region string `json:"region,omitempty"`

	// Bucket that holds the artifacts.
	Bucket string `json:"bucket"`

	// Prefix is the key prefix within the bucket.
	//
	// +optional
	Prefix string `json:"prefix,omitempty"`

	// ForcePathStyle addresses the bucket as a path segment rather than a
	// virtual host. MinIO and most self-hosted gateways need it.
	//
	// +optional
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// CredentialsSecretRef holds static credentials. Omit it to use the
	// pod's ambient identity (IRSA, workload identity, instance role).
	//
	// +optional
	CredentialsSecretRef *S3CredentialsReference `json:"credentialsSecretRef,omitempty"`

	// ServerSideEncryption requests SSE, for example AES256 or aws:kms.
	//
	// +optional
	ServerSideEncryption string `json:"serverSideEncryption,omitempty"`

	// KMSKeyID names the key when ServerSideEncryption is aws:kms.
	//
	// +optional
	KMSKeyID string `json:"kmsKeyID,omitempty"`

	// StorageClass for uploaded objects, for example STANDARD_IA.
	//
	// +optional
	StorageClass string `json:"storageClass,omitempty"`

	// CABundleSecretRef holds a CA bundle for a private-CA endpoint.
	//
	// +optional
	CABundleSecretRef *SecretKeyReference `json:"caBundleSecretRef,omitempty"`

	// InsecureSkipVerify disables TLS verification. It exists for lab
	// clusters; it should never be set against anything that matters.
	//
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// S3CredentialsReference locates static S3 credentials in a Secret.
type S3CredentialsReference struct {
	// Name of the Secret.
	Name string `json:"name"`

	// AccessKeyIDKey is the key holding the access key ID.
	//
	// +kubebuilder:default=access-key-id
	// +optional
	AccessKeyIDKey string `json:"accessKeyIDKey,omitempty"`

	// SecretAccessKeyKey is the key holding the secret access key.
	//
	// +kubebuilder:default=secret-access-key
	// +optional
	SecretAccessKeyKey string `json:"secretAccessKeyKey,omitempty"`

	// SessionTokenKey is the key holding an optional session token.
	//
	// +optional
	SessionTokenKey string `json:"sessionTokenKey,omitempty"`
}

// FilesystemDestination describes a PersistentVolume that holds artifacts.
// It is what makes on-prem and air-gapped clusters first-class.
type FilesystemDestination struct {
	// ExistingClaim names a PersistentVolumeClaim to write into. Prefer
	// ReadWriteMany so restore Jobs can be scheduled anywhere.
	//
	// +optional
	ExistingClaim string `json:"existingClaim,omitempty"`

	// ClaimTemplate creates the claim instead of adopting one.
	//
	// +optional
	ClaimTemplate *VolumeClaimTemplate `json:"claimTemplate,omitempty"`

	// Path is the directory prefix within the volume.
	//
	// +optional
	Path string `json:"path,omitempty"`
}

// VolumeClaimTemplate is the subset of PVC spec the operator renders.
type VolumeClaimTemplate struct {
	// Size of the volume.
	//
	// +kubebuilder:default="8Gi"
	Size string `json:"size,omitempty"`

	// StorageClassName selects the class. Empty uses the cluster default.
	//
	// +optional
	StorageClassName string `json:"storageClassName,omitempty"`

	// AccessModes for the claim.
	//
	// +optional
	AccessModes []string `json:"accessModes,omitempty"`

	// Annotations added to the claim.
	//
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ChecksumSpec records the digest of a stored artifact.
type ChecksumSpec struct {
	// Algorithm used, always sha256 today.
	Algorithm string `json:"algorithm,omitempty"`

	// Value is the hex-encoded digest.
	Value string `json:"value,omitempty"`
}

// findCondition returns the condition with the given type, or nil.
func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}

	return nil
}

// IsConditionTrue reports whether the named condition is present and True.
func IsConditionTrue(conditions []metav1.Condition, conditionType string) bool {
	c := findCondition(conditions, conditionType)

	return c != nil && c.Status == metav1.ConditionTrue
}
