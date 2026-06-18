# Logging reference

Carved from the comprehensive Go style guide. Covers logger as a
dependency, structured logging in production, level discipline,
metrics-vs-logs investment order, and `log/slog` patterns.

---

## Loggers are explicit dependencies

Never use package-level loggers. Pass loggers as constructor parameters:

```go
// BAD: global logger
package service

var logger = log.New(os.Stderr, "", log.LstdFlags)

func Process() {
    logger.Println("processing")  // hidden dependency
}

// GOOD: explicit dependency
type Service struct {
    logger *log.Logger
}

func NewService(logger *log.Logger) *Service {
    if logger == nil {
        logger = log.New(io.Discard, "", 0)  // no-op default
    }
    return &Service{logger: logger}
}
```

## Use structured logging in production

All production codebases require structured logging. GitLab uses Logrus via
LabKit, Thanos uses go-kit/log:

```go
// Thanos style: go-kit/log
level.Info(logger).Log(
    "msg", "compaction completed",
    "duration", elapsed,
    "blocks", blockCount,
)

// GitLab style: Logrus
logrus.WithFields(logrus.Fields{
    "duration": elapsed,
    "blocks":   blockCount,
}).Info("compaction completed")
```

Log keys should be camelCase and consistent across the codebase. Messages should
be lowercase.

## Log levels: info and debug usually suffice

Peter Bourgon's guidance: **avoid fine-grained log levels**. Info for important
operational events, debug for investigation. Warn and error for exceptional
situations requiring attention.

Logging is expensive. Log only actionable information that a human or machine
will actually read.

## Instrument everything, investigate selectively

Metrics are cheap; logging is expensive. Instrument all significant components
with:

- **USE method** for resources: Utilization, Saturation, Error count
- **RED method** for endpoints: Request count, Error count, Duration

Investment order: basic metrics first, then structured logging, then distributed
tracing at scale.

---

## Structured logging with log/slog

Go 1.21 added `log/slog` to the standard library, replacing the need for
third-party structured logging libraries like zap, zerolog, or logrus for most
use cases.

**Core principles:**

1. Pass `*slog.Logger` as an explicit dependency — never use package globals
2. Use `slog.With` to add common attributes at construction time
3. Use context-aware methods (`InfoContext`, `ErrorContext`) to propagate
   request-scoped data via middleware
4. Use `slog.Group` for nested attributes

```go
// Constructor injection
type OrderService struct {
    logger *slog.Logger
    db     *sql.DB
}

func NewOrderService(logger *slog.Logger, db *sql.DB) *OrderService {
    return &OrderService{
        logger: logger.With(slog.String("component", "order-service")),
        db:     db,
    }
}

func (s *OrderService) PlaceOrder(ctx context.Context, order Order) error {
    s.logger.InfoContext(ctx, "placing order",
        slog.Int64("user_id", order.UserID),
        slog.String("item", order.Item),
        slog.Float64("total", order.Total),
    )
    // ...
}
```

**Handler configuration in main:**

```go
func main() {
    var handler slog.Handler
    if os.Getenv("ENV") == "production" {
        handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
            Level: slog.LevelInfo,
        })
    } else {
        handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
            Level: slog.LevelDebug,
        })
    }
    logger := slog.New(handler)
    slog.SetDefault(logger) // for libraries that use slog.Default()
}
```

**LogValuer for expensive computations:**

```go
type LazyJSON struct{ v any }

func (l LazyJSON) LogValue() slog.Value {
    data, _ := json.Marshal(l.v)
    return slog.StringValue(string(data))
}

// Only marshals if the log level is enabled
logger.Debug("request body", slog.Any("body", LazyJSON{req}))
```
