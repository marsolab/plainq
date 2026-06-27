# Terminal UI (TUI)

PlainQ ships an interactive terminal UI built with
[Bubble Tea](https://github.com/charmbracelet/bubbletea). It is a fast way to
browse queues and push or pull messages without leaving the terminal.

```bash
plainq tui -grpc.addr localhost:8080
```

The TUI talks to the same gRPC API as the CLI, so it works against any running
PlainQ server (local, container, or Kubernetes via `kubectl port-forward`).

## Views

### Queue list (start screen)

A table of every queue with its id, name, visibility timeout, max receive
attempts, and eviction policy.

| Key | Action |
| --- | --- |
| `↑`/`k`, `↓`/`j` | Move the selection |
| `enter` | Open the selected queue |
| `r` | Refresh the list |
| `d` | Delete the selected queue (force) |
| `q` / `ctrl+c` | Quit |

### Queue detail

Shows the selected queue's properties and the most recently received messages.

| Key | Action |
| --- | --- |
| `g` | Receive a batch of messages |
| `s` | Compose and send a message |
| `p` | Purge the queue |
| `esc` | Back to the queue list |
| `q` / `ctrl+c` | Quit |

### Send composer

A single-line editor for the message body.

| Key | Action |
| --- | --- |
| `enter` | Send the message |
| `esc` | Cancel and return to the detail view |

## Notes

- Received messages become invisible for the queue's visibility timeout. To
  acknowledge (delete) them from a script instead, use
  `plainq receive -ack` or `plainq delete-message` — see the
  [CLI guide](cli.md).
- The status line at the bottom reports the result of the last action; errors
  are shown in red.
- The TUI requires an interactive terminal. In non-interactive contexts
  (pipes, CI), use the CLI with `-json` instead.
