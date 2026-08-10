# `plainq` Protobuf Schema

This repository defines a protobuf schema for communication with
plainq server.

Any gRPC compatible language can use this schema to implement a
custom client for communication with plainq server.

## Documentation

All RPC methods and their request and response structures are documented.
You can find a documentation here:

[https://buf.build/plainq/schema/docs/main:v1](https://buf.build/plainq/schema/docs/main:v1)


## SDKs

Buf Schema Registry automatically generate SDKs for some popular programming languages.
You can find them here:

[https://buf.build/plainq/schema/sdks/main](https://buf.build/plainq/schema/sdks/main)

## Publishing policy

Schema commits pushed to [buf.build/plainq/schema](https://buf.build/plainq/schema)
are immutable consumer contracts. **Do not delete, recreate, or replace published
BSR modules, labels, or commit history.** Exact generated-SDK pins (for example
`buf.build/gen/go/plainq/schema/...@v…-<commit>.1`) must remain downloadable.
Fix forward with a new compatible commit; never rewrite registry history to
“clean up” a bad publish.

CI publishes via `.github/workflows/schema-release.yaml` using the `BUF_TOKEN`
repository secret (a Buf token with push rights to `plainq/schema`).

## Contribution

Feel free to submit your PRs, but please provide detailed description about `how` and `why`.