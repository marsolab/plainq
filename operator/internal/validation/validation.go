// Package validation holds the admission rules as pure functions.
//
// They live apart from the webhook wiring so they can be tested without an
// API server, and so the reconcilers can re-check the ones whose answer
// depends on live cluster state.
package validation

import (
	"fmt"
	"strings"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// ValidatePlainQ checks a PlainQ on create.
//
//nolint:gocyclo,cyclop // One branch per rule; the list is the specification.
func ValidatePlainQ(pq *plainqv1alpha1.PlainQ) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")
	storage := spec.Child("storage")
	cluster := spec.Child("cluster")

	// Cluster mode replicates through Raft over each node's own embedded
	// database. There is nothing to replicate on a shared Postgres backend,
	// and the two consistency models would fight.
	if pq.Spec.Cluster.Enabled && pq.Spec.Storage.Driver == plainqv1alpha1.StoragePostgres {
		errs = append(errs, field.Invalid(cluster.Child("enabled"), true,
			"cluster mode requires storage.driver=sqlite: a shared Postgres backend has "+
				"nothing for Raft to replicate"))
	}

	// SQLite is one file on one ReadWriteOnce volume. More than one replica
	// pointed at it is not slower, it is corruption.
	if !pq.Spec.Cluster.Enabled &&
		pq.Spec.Storage.Driver == plainqv1alpha1.StorageSQLite &&
		pq.Spec.Replicas > 1 {
		errs = append(errs, field.Invalid(spec.Child("replicas"), pq.Spec.Replicas,
			"the sqlite driver is single-writer and pinned to one replica; "+
				"enable cluster mode or use storage.driver=postgres to run more"))
	}

	if pq.Spec.Cluster.Enabled && pq.Spec.Cluster.Replicas < 1 {
		errs = append(errs, field.Invalid(cluster.Child("replicas"), pq.Spec.Cluster.Replicas,
			"a cluster needs at least one node"))
	}

	if pq.Spec.Cluster.Enabled && pq.Spec.Cluster.Discovery == plainqv1alpha1.DiscoveryCustom &&
		pq.Spec.Cluster.DiscoverySpec == "" {
		errs = append(errs, field.Required(cluster.Child("discoverySpec"),
			"discovery=custom needs an explicit spec string"))
	}

	if pq.Spec.Storage.Driver == plainqv1alpha1.StoragePostgres &&
		pq.Spec.Storage.Postgres.DSNSecretRef == nil {
		errs = append(errs, field.Required(storage.Child("postgres", "dsnSecretRef"),
			"the postgres driver needs a DSN secret reference"))
	}

	if pq.Spec.Autoscaling.Enabled && pq.Spec.Storage.Driver != plainqv1alpha1.StoragePostgres {
		errs = append(errs, field.Invalid(spec.Child("autoscaling", "enabled"), true,
			"autoscaling applies only to storage.driver=postgres; the sqlite driver is "+
				"pinned to one replica"))
	}

	if size := pq.Spec.Storage.SQLite.Persistence.Size; size != "" {
		if _, err := resource.ParseQuantity(size); err != nil {
			errs = append(errs, field.Invalid(
				storage.Child("sqlite", "persistence", "size"), size, "not a valid quantity"))
		}
	}

	return errs
}

// ValidatePlainQUpdate checks the fields that cannot change once set.
func ValidatePlainQUpdate(old, updated *plainqv1alpha1.PlainQ) field.ErrorList {
	errs := ValidatePlainQ(updated)

	spec := field.NewPath("spec")

	// Changing the driver would abandon the data rather than migrate it.
	if old.Spec.Storage.Driver != "" && old.Spec.Storage.Driver != updated.Spec.Storage.Driver {
		errs = append(errs, field.Invalid(spec.Child("storage", "driver"), updated.Spec.Storage.Driver,
			"storage.driver is immutable: create a new instance and restore into it"))
	}

	// Turning clustering on or off changes the storage layout, the port
	// surface and the failure modes at once. There is no in-place path.
	if old.Spec.Cluster.Enabled != updated.Spec.Cluster.Enabled {
		errs = append(errs, field.Invalid(spec.Child("cluster", "enabled"), updated.Spec.Cluster.Enabled,
			"cluster.enabled is immutable: create a new instance and restore into it"))
	}

	errs = append(errs, validateVolumeNotShrunk(old, updated)...)

	return errs
}

func validateVolumeNotShrunk(old, updated *plainqv1alpha1.PlainQ) field.ErrorList {
	oldSize := old.Spec.Storage.SQLite.Persistence.Size
	newSize := updated.Spec.Storage.SQLite.Persistence.Size

	if oldSize == "" || newSize == "" {
		return nil
	}

	oldQuantity, err := resource.ParseQuantity(oldSize)
	if err != nil {
		return nil
	}

	newQuantity, err := resource.ParseQuantity(newSize)
	if err != nil {
		return nil
	}

	if newQuantity.Cmp(oldQuantity) < 0 {
		return field.ErrorList{field.Invalid(
			field.NewPath("spec", "storage", "sqlite", "persistence", "size"), newSize,
			"PersistentVolumeClaims cannot shrink")}
	}

	return nil
}

// ValidateScaleIn checks one step of a cluster drain against the membership
// as it stands right now.
//
// Quorum is recomputed after every committed membership change, which is what
// makes a stepwise drain safe: a healthy 3-node cluster has a quorum of 2 and
// can go to 2 (quorum 2), and from there to 1 (quorum 1). A rule that
// compared the final target of 1 against the original quorum of 2 would
// reject a drain that is safe at every step — and the supervised removal
// sequence would never run.
//
// So this validates a single removal, and the reconciler calls it once per
// step rather than once per edit.
func ValidateScaleIn(currentVoters, healthyVoters, target int32) error {
	if target < 1 {
		return fmt.Errorf("a cluster cannot scale below one node (target %d)", target)
	}

	if target >= currentVoters {
		// Not a scale-in.
		return nil
	}

	// The cluster has to be able to commit the configuration change that
	// removes the member. That needs a quorum of the configuration as it
	// stands before the removal.
	required := plainqv1alpha1.Quorum(currentVoters)
	if healthyVoters < required {
		return fmt.Errorf(
			"cannot remove a member: %d of %d voters are healthy but %d are needed to commit "+
				"the configuration change",
			healthyVoters, currentVoters, required)
	}

	return nil
}

// ValidatePlainQQueue checks a queue.
//
//nolint:cyclop // One branch per rule.
func ValidatePlainQQueue(q *plainqv1alpha1.PlainQQueue) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")

	if err := validateServerRef(q.Spec.ServerRef, spec.Child("serverRef")); err != nil {
		errs = append(errs, err)
	}

	if q.Spec.EvictionPolicy == plainqv1alpha1.EvictionDeadLetter &&
		q.Spec.DeadLetterQueueRef == nil && q.Spec.DeadLetterQueueID == "" {
		errs = append(errs, field.Required(spec.Child("deadLetterQueueRef"),
			"evictionPolicy=DeadLetter needs somewhere to put evicted messages"))
	}

	// A queue that dead-letters into itself is an eviction loop.
	if q.Spec.DeadLetterQueueRef != nil && q.Spec.DeadLetterQueueRef.Name == q.Name {
		errs = append(errs, field.Invalid(spec.Child("deadLetterQueueRef", "name"),
			q.Spec.DeadLetterQueueRef.Name,
			"a queue cannot be its own dead-letter queue"))
	}

	if q.Spec.DeadLetterQueueRef != nil && q.Spec.DeadLetterQueueID != "" {
		errs = append(errs, field.Invalid(spec.Child("deadLetterQueueID"), q.Spec.DeadLetterQueueID,
			"set deadLetterQueueRef or deadLetterQueueID, not both"))
	}

	// Recreating a queue destroys every message in it, so it is not
	// something to discover after the fact.
	if q.Spec.UpdatePolicy == plainqv1alpha1.UpdateRecreate && !q.Spec.AllowDataLoss {
		errs = append(errs, field.Invalid(spec.Child("updatePolicy"), q.Spec.UpdatePolicy,
			"updatePolicy=Recreate deletes every message in the queue; set allowDataLoss=true "+
				"to confirm"))
	}

	return errs
}

// ValidatePlainQQueueUpdate additionally rejects a rename.
func ValidatePlainQQueueUpdate(old, updated *plainqv1alpha1.PlainQQueue) field.ErrorList {
	errs := ValidatePlainQQueue(updated)

	// The server has no rename. Changing the name would create a second
	// queue and abandon the first, silently.
	if old.ResolvedQueueName() != updated.ResolvedQueueName() {
		errs = append(errs, field.Invalid(field.NewPath("spec", "queueName"),
			updated.ResolvedQueueName(),
			"queueName is immutable: the server has no rename, so this would create a second "+
				"queue and abandon the first"))
	}

	return errs
}

// ValidatePlainQTopic checks a topic.
func ValidatePlainQTopic(t *plainqv1alpha1.PlainQTopic) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")

	if err := validateServerRef(t.Spec.ServerRef, spec.Child("serverRef")); err != nil {
		errs = append(errs, err)
	}

	for i, sub := range t.Spec.Subscriptions {
		path := spec.Child("subscriptions").Index(i)

		switch {
		case sub.QueueRef == nil && sub.QueueID == "":
			errs = append(errs, field.Required(path, "a subscription needs queueRef or queueID"))

		case sub.QueueRef != nil && sub.QueueID != "":
			errs = append(errs, field.Invalid(path, sub, "set queueRef or queueID, not both"))
		}
	}

	return errs
}

// ValidatePlainQAccount checks an account against the instance it targets.
//
// registrationEnabled is the target's spec.auth.registration. It is a
// parameter rather than a lookup so the rule stays a pure function; the
// webhook resolves the instance and passes it in.
func ValidatePlainQAccount(a *plainqv1alpha1.PlainQAccount, registrationEnabled bool) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")

	if err := validateServerRef(a.Spec.ServerRef, spec.Child("serverRef")); err != nil {
		errs = append(errs, err)
	}

	if !strings.Contains(a.Spec.Email, "@") {
		errs = append(errs, field.Invalid(spec.Child("email"), a.Spec.Email, "not an email address"))
	}

	// The only account-creation route after the first admin is
	// /api/v1/account/signup, and its handler refuses whenever
	// auth.registration is off — before it reads the body, and regardless of
	// any admin token. Rejecting here turns a 401 loop in a controller log
	// into an admission error that names the cause.
	if !a.Spec.Bootstrap && !registrationEnabled {
		errs = append(errs, field.Forbidden(spec.Child("bootstrap"),
			"a non-bootstrap account requires spec.auth.registration=true on the target PlainQ: "+
				"/api/v1/account/signup is the only creation route the server has and it refuses "+
				"when self-registration is disabled"))
	}

	return errs
}

// ValidatePlainQBackupPolicy checks a backup regime.
func ValidatePlainQBackupPolicy(p *plainqv1alpha1.PlainQBackupPolicy, driver plainqv1alpha1.StorageDriver) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")

	if err := validateServerRef(p.Spec.ServerRef, spec.Child("serverRef")); err != nil {
		errs = append(errs, err)
	}

	errs = append(errs, validateDestination(p.Spec.Destination, spec.Child("destination"))...)

	if p.Spec.Schedule.Enabled {
		if p.Spec.Schedule.Cron == "" {
			errs = append(errs, field.Required(spec.Child("schedule", "cron"),
				"a schedule needs a cron expression"))
		} else if err := ValidateCron(p.Spec.Schedule.Cron); err != nil {
			errs = append(errs, field.Invalid(spec.Child("schedule", "cron"), p.Spec.Schedule.Cron,
				err.Error()))
		}

		errs = append(errs, validateEngineMatchesDriver(p.Spec.Schedule.Engine, driver,
			spec.Child("schedule", "engine"))...)
	}

	if p.Spec.Encryption.Enabled && p.Spec.Encryption.SecretRef == nil {
		errs = append(errs, field.Required(spec.Child("encryption", "secretRef"),
			"encryption needs a key"))
	}

	return errs
}

func validateEngineMatchesDriver(
	engine plainqv1alpha1.BackupEngine,
	driver plainqv1alpha1.StorageDriver,
	path *field.Path,
) field.ErrorList {
	if driver == "" || engine == "" {
		return nil
	}

	switch engine {
	case plainqv1alpha1.EnginePostgresDump:
		if driver != plainqv1alpha1.StoragePostgres {
			return field.ErrorList{field.Invalid(path, engine,
				"the PostgresDump engine needs storage.driver=postgres")}
		}

	case plainqv1alpha1.EngineOnline, plainqv1alpha1.EngineVolumeSnapshot, plainqv1alpha1.EngineLitestream:
		if driver != plainqv1alpha1.StorageSQLite {
			return field.ErrorList{field.Invalid(path, engine,
				fmt.Sprintf("the %s engine needs storage.driver=sqlite", engine))}
		}
	}

	return nil
}

// ValidatePlainQRestore checks a restore.
func ValidatePlainQRestore(r *plainqv1alpha1.PlainQRestore) field.ErrorList {
	var errs field.ErrorList

	spec := field.NewPath("spec")
	source := spec.Child("source")

	sources := 0

	if r.Spec.Source.BackupRef != nil {
		sources++
	}

	if r.Spec.Source.PolicyRef != nil {
		sources++
	}

	if r.Spec.Source.Location != "" {
		sources++
	}

	if sources != 1 {
		errs = append(errs, field.Invalid(source, r.Spec.Source,
			"set exactly one of backupRef, policyRef or location"))
	}

	errs = append(errs, validateRestoreTarget(r, spec)...)

	return errs
}

func validateRestoreTarget(r *plainqv1alpha1.PlainQRestore, spec *field.Path) field.ErrorList {
	var errs field.ErrorList

	target := spec.Child("target")

	switch r.Spec.Target.Strategy {
	case plainqv1alpha1.RestoreInPlace:
		if r.Spec.Target.InPlace == nil {
			errs = append(errs, field.Required(target.Child("inPlace"),
				"the InPlace strategy needs a target instance"))
		}

		// InPlace overwrites a live database. It should be a decision, not a
		// reflex.
		if !r.Spec.AllowDataLoss {
			errs = append(errs, field.Invalid(spec.Child("allowDataLoss"), false,
				"the InPlace strategy overwrites the target's database; set allowDataLoss=true "+
					"to confirm, or use the NewInstance strategy, which leaves it untouched"))
		}

	case plainqv1alpha1.RestoreNewInstance, "":
		if r.Spec.Target.NewInstance == nil {
			errs = append(errs, field.Required(target.Child("newInstance"),
				"the NewInstance strategy needs a name for the instance to create"))

			return errs
		}

		errs = append(errs, validateRawLocationTarget(r, target)...)
	}

	return errs
}

// validateRawLocationTarget enforces that a raw-artifact restore carries a
// complete instance spec.
//
// A raw location is bytes in a bucket: no PlainQBackup, possibly no policy,
// possibly no surviving source instance — which is the whole point of the
// case. Nothing can tell the operator the storage driver, a compatible server
// version, or the volume size, and guessing produces an instance that either
// will not start or opens a database it cannot read.
func validateRawLocationTarget(r *plainqv1alpha1.PlainQRestore, target *field.Path) field.ErrorList {
	if r.Spec.Source.Location == "" {
		// backupRef and policyRef both carry a base to inherit from.
		return nil
	}

	path := target.Child("newInstance", "spec")
	spec := r.Spec.Target.NewInstance.Spec

	if spec == nil {
		return field.ErrorList{field.Required(path,
			"a restore from source.location has nothing to inherit a spec from: no backup, "+
				"no policy and possibly no source instance. Provide a complete spec, including "+
				"storage.driver, version and volume size")}
	}

	var missing []string

	if spec.Storage.Driver == "" {
		missing = append(missing, "storage.driver")
	}

	if spec.Version == "" && spec.Image.Tag == "" {
		missing = append(missing, "version")
	}

	if spec.Storage.Driver == plainqv1alpha1.StorageSQLite &&
		plainqv1alpha1.BoolValue(spec.Storage.SQLite.Persistence.Enabled, true) &&
		spec.Storage.SQLite.Persistence.Size == "" {
		missing = append(missing, "storage.sqlite.persistence.size")
	}

	if len(missing) > 0 {
		return field.ErrorList{field.Required(path,
			"a restore from source.location must specify "+strings.Join(missing, ", ")+
				": there is no backup or policy to inherit them from")}
	}

	return nil
}

// ValidateAliasClaim rejects a second instance claiming an alias that is
// already held. An alias with two holders is not a cutover.
//
// holder is the instance currently holding the alias, empty when it is free.
func ValidateAliasClaim(alias, claimant, holder string) *field.Error {
	if alias == "" || holder == "" || holder == claimant {
		return nil
	}

	return field.Invalid(field.NewPath("spec", "networking", "alias", "name"), alias,
		fmt.Sprintf("alias %q is already held by PlainQ %q; clear it there first so the "+
			"cutover stays a single atomic move", alias, holder))
}

func validateServerRef(ref plainqv1alpha1.ServerReference, path *field.Path) *field.Error {
	switch {
	case ref.Name == "" && ref.Endpoint == "":
		return field.Required(path, "set name or endpoint")

	case ref.Name != "" && ref.Endpoint != "":
		return field.Invalid(path, ref, "set name or endpoint, not both")

	case ref.Endpoint != "" && ref.CredentialsSecretRef == nil:
		return field.Required(path.Child("credentialsSecretRef"),
			"an external endpoint needs credentials")
	}

	return nil
}

func validateDestination(dest plainqv1alpha1.Destination, path *field.Path) field.ErrorList {
	switch {
	case dest.S3 == nil && dest.Filesystem == nil:
		return field.ErrorList{field.Required(path, "set s3 or filesystem")}

	case dest.S3 != nil && dest.Filesystem != nil:
		return field.ErrorList{field.Invalid(path, dest, "set s3 or filesystem, not both")}
	}

	if dest.S3 != nil && dest.S3.Bucket == "" {
		return field.ErrorList{field.Required(path.Child("s3", "bucket"), "a bucket is required")}
	}

	if dest.Filesystem != nil &&
		dest.Filesystem.ExistingClaim == "" && dest.Filesystem.ClaimTemplate == nil {
		return field.ErrorList{field.Required(path.Child("filesystem"),
			"set existingClaim or claimTemplate")}
	}

	return nil
}
