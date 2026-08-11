# Driving PlainQ from an agent

The `plainq` CLI is built to be driven by a program that has never seen it
before — an AI agent, a deploy script, a CI job. This page is the contract that
makes that possible. For narrative usage see the [CLI guide](cli.md); for a
lookup table see the [CLI reference](../reference/cli.md).

## The discovery loop

Three commands, in this order, are enough to go from "there is a binary called
plainq" to a correct invocation. None of them needs a server:

```shell
plainq -h                        # what commands exist, and the conventions
plainq schema -target=cli -json  # the whole surface, machine-readable
plainq <command> -h              # one command in depth, with examples
```

`plainq schema -target=cli -json` returns:

```jsonc
{
  "cli": {
    "binary": "plainq",
    "description": "...",
    "conventions": ["..."],       // rules that hold for every command
    "exitCodes": [{"code": 0, "meaning": "success"}, ...],
    "commands": [
      {
        "path": "plainq send",              // full invocation prefix
        "name": "send",
        "short": "Send one or more messages to a queue",
        "long": "...",
        "usage": "plainq send [flags] <queue-id>",
        "effect": "mutating",               // read-only | mutating | destructive
        "blocking": false,                  // true = runs until interrupted
        "arguments": [
          {"name": "queue-id", "description": "...", "required": true, "variadic": false}
        ],
        "flags": [
          {"name": "message", "type": "string", "default": "",
           "usage": "message body to send", "repeatable": true}
        ],
        "examples": [{"description": "...", "command": "..."}],
        "subcommands": []
      }
    ]
  },
  "grpc": [ { "service": "v1.PlainQService", "methods": [...] } ]
}
```

The flag list is read from the live flag set at runtime, so it cannot drift from
what the binary actually accepts. A test in `cmd/` fails the build if a command
ships without a description, an effect, an example, or usage text on every flag.

## The contract

**Argument order does not matter.** Flags may appear before or after positional
arguments; `plainq send -message=hi <queue-id>` and
`plainq send <queue-id> -message=hi` are the same command. Both `-flag value`
and `-flag=value` work, with one or two leading dashes.

**Streams are separated.** Command output goes to stdout, diagnostics to stderr.
Capturing stdout alone always yields parseable output.

**Exit codes are meaningful.**

| Code | Meaning | What to do |
| ---- | ------- | ---------- |
| `0` | Success | Continue. |
| `1` | Ran but failed — server unreachable, queue not found, request rejected | Read stderr; retrying may help if the cause was transient. |
| `2` | Usage error — unknown flag, missing or malformed argument | Fix the command line. Retrying it unchanged will not help. |

**Every command declares its effect.** `read-only` commands are safe to run
while exploring. `mutating` commands change state. `destructive` commands
(`purge`, `delete`, `delete-message`, `cluster leave`) remove data immediately,
with no confirmation prompt and no undo — do not run them to "see what happens".

**Two commands block.** `serve` and `tui` run until interrupted; `tui` also
needs a terminal. Everything `tui` offers is available as a plain command.

**Nothing is interactive.** No command prompts, and none reads stdin unless you
pass `-file=-`.

## Reading `-json` output

`-json` emits the server's response as protobuf JSON, which has three
consequences worth knowing before writing a `jq` expression:

- Fields at their zero value are **omitted**. An empty response prints `{}`.
- 64-bit integers are **quoted strings**: `"visibilityTimeoutSeconds": "30"`.
- Byte fields — notably a message body — are **base64**:

  ```shell
  plainq receive -json "$QID" | jq -r '.messages[].body | @base64d'
  ```

## Pointing at a server

In order of precedence:

1. `--grpc.addr` on the command line
2. `PLAINQ_ADDR` in the environment
3. the current context (`plainq ctx list`)
4. `localhost:8080`

`PLAINQ_ADDR` is usually the right lever for an agent: set it once for the
session instead of threading a flag through every call.

## A worked session

```shell
# 1. Learn the surface. No server needed.
plainq schema -target=cli -json > surface.json

# 2. Point at a server.
export PLAINQ_ADDR=localhost:8080

# 3. Create a queue and keep its id. Names are not ids.
QID=$(plainq create orders)

# 4. Enqueue. Repeat -message, or stream a file.
plainq send "$QID" -message='{"order_id":42}' -message='{"order_id":43}'

# 5. Dequeue without acknowledging, and decode the bodies.
plainq receive "$QID" -batch=10 -json | jq -r '.messages[].body | @base64d'

# 6. Acknowledge once the work has actually succeeded.
plainq delete-message "$QID" <message-id>...

# ...or dequeue and acknowledge in one step when the work is the read itself.
plainq receive "$QID" -batch=10 -ack -json
```

Receiving from an empty queue is not an error: it prints nothing and exits `0`.

## Common failures

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| `cannot reach a PlainQ server at "localhost:8080"` | No server, or the wrong address | Start one with `plainq serve`, or set `PLAINQ_ADDR` |
| `invalid queue id "orders"` (exit 2) | A queue **name** was passed where an **id** is required | Use the id from `plainq create` or `plainq list` |
| `no messages: provide -message and/or -file` (exit 2) | `send` was called with nothing to send | Pass `-message` or `-file` |
| `flag provided but not defined` (exit 2) | Misspelled flag | Check `plainq <command> -h` |
| A `.body` value looks like gibberish | It is base64 | Decode it: `jq -r '.messages[].body \| @base64d'` |
