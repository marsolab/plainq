# Release notes

## Unreleased — Stable queue-backed pub/sub v1

PlainQ now treats the existing topic, subscription, and publish protobuf and
HTTP shapes as the stable v1 contract. Existing wire/API shapes remain
compatible. Six `plainq topic` commands, Prometheus families, typed telemetry
history, and two Houston graphs are additive.

Publish now attempts every selected destination even after one queue fails. An
errored publish may therefore reach more queues than the same request on an
older binary. Copies already retained are not rolled back, so retrying an
errored publish can create duplicates. Consumers should keep their normal
at-least-once idempotency boundary.

Historical delivery-failure and subscription-lifecycle series start when the
upgraded binary begins collecting them. They are not backfilled. Missing older
ranges are reported as `notRecorded`, not fabricated as zero.
