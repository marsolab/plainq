---
name: go-http
description: >-
  Building HTTP services in Go with the Chi router and stdlib `net/http`.
  ALWAYS use this skill when writing or reviewing Go HTTP code — defining
  routes with `chi.Router`, middleware (`chi.Use`, `middleware.Logger`,
  `middleware.Recoverer`, `middleware.RequestID`), handler signatures,
  request decoding, JSON responses, status codes from typed errors,
  graceful shutdown with `http.Server.Shutdown`, `httptest` patterns,
  service project layout (`cmd/server`, `internal/handler`, `internal/service`),
  and timeouts (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`). Pair with
  go-sql for the data layer, go-logging for request-scoped logging,
  go-errors for status code mapping, and go-testing for handler tests.
version: 1.0.0
tags:
  - go
  - golang
  - http
  - chi
  - api
  - rest
  - service
---

# Go HTTP

Build HTTP services with the stdlib `net/http` and
[Chi](https://github.com/go-chi/chi) for routing. Chi is small, has
zero dependencies, and is fully `net/http`-compatible.

For handler tests with `httptest`, see go-testing. For the data layer,
see go-sql.

## Project layout

```text
myservice/
├── cmd/server/main.go
├── internal/
│   ├── handler/         # HTTP-specific code: decoding, status codes
│   ├── service/         # business logic, no HTTP dependencies
│   └── storage/         # data access (sqlc-generated)
├── db/
│   ├── migrations/
│   └── queries/
├── go.mod
├── Makefile
└── .golangci.yml
```

The handler depends on the service; the service depends on storage.
Reverse direction is wrong and Chi types should never appear below
`internal/handler`.

## main.go pattern: flags + graceful shutdown

```go
func main() {
    addr := flag.String("addr", ":8080", "listen address")
    flag.Parse()

    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

    srv := &http.Server{
        Addr:         *addr,
        Handler:      setupRoutes(logger),
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }

    go func() {
        sigint := make(chan os.Signal, 1)
        signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
        <-sigint

        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := srv.Shutdown(ctx); err != nil {
            logger.Error("shutdown", slog.Any("err", err))
        }
    }()

    logger.Info("listening", slog.String("addr", *addr))
    if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
        logger.Error("server", slog.Any("err", err))
        os.Exit(1)
    }
}
```

`ListenAndServe` returns `http.ErrServerClosed` after a graceful
shutdown — that's expected, not an error.

## Routes with Chi

```go
func setupRoutes(logger *slog.Logger) http.Handler {
    r := chi.NewRouter()

    r.Use(middleware.RequestID)
    r.Use(middleware.RealIP)
    r.Use(middleware.Recoverer)
    r.Use(middleware.Timeout(30 * time.Second))
    r.Use(loggingMiddleware(logger))

    r.Get("/healthz", healthz)

    r.Route("/api/v1", func(r chi.Router) {
        r.Get("/users", listUsers)
        r.Post("/users", createUser)
        r.Get("/users/{id}", getUser)
    })
    return r
}
```

Common Chi middleware: `RequestID`, `RealIP`, `Logger` (or your own
slog-based one), `Recoverer`, `Timeout`, `Compress`. Apply auth middleware
inside `r.Group` or `r.Route` for the routes that need it.

## Handler signature

```go
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
    var req CreateUserRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        writeError(w, http.StatusBadRequest, "invalid json")
        return
    }
    defer r.Body.Close()

    user, err := h.svc.CreateUser(r.Context(), req.Email, req.Name)
    if err != nil {
        writeServiceError(w, err)
        return
    }
    writeJSON(w, http.StatusCreated, user)
}
```

Pass `r.Context()` down to the service. That context is cancelled if the
client disconnects or the timeout middleware fires.

## URL parameters

```go
id := chi.URLParam(r, "id")
```

For typed values, parse and validate explicitly:

```go
id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
if err != nil {
    writeError(w, http.StatusBadRequest, "invalid id")
    return
}
```

## Mapping errors to status codes

Use typed errors from the service layer; the handler translates:

```go
func writeServiceError(w http.ResponseWriter, err error) {
    var verr *service.ValidationError
    switch {
    case errors.Is(err, service.ErrNotFound):
        writeError(w, http.StatusNotFound, "not found")
    case errors.As(err, &verr):
        writeError(w, http.StatusBadRequest, verr.Error())
    default:
        // log unexpected; never leak the inner error
        slog.Default().Error("internal", slog.Any("err", err))
        writeError(w, http.StatusInternalServerError, "internal error")
    }
}
```

The service layer doesn't know about HTTP. The handler is the only
layer that maps errors to status codes.

## JSON helpers

```go
func writeJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
    writeJSON(w, status, map[string]string{"error": msg})
}
```

## Testing handlers

```go
func TestCreateUser(t *testing.T) {
    h := &UserHandler{svc: &fakeSvc{user: User{ID: 1, Name: "ada"}}}
    r := chi.NewRouter()
    r.Post("/users", h.Create)

    body := strings.NewReader(`{"email":"a@b.c","name":"ada"}`)
    req := httptest.NewRequest(http.MethodPost, "/users", body)
    rec := httptest.NewRecorder()
    r.ServeHTTP(rec, req)

    if rec.Code != http.StatusCreated {
        t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
    }
}
```

`httptest.NewRequest` constructs a request without a network listener.
`httptest.NewRecorder` captures the response.

## Timeouts

Always set them. The defaults (`0`) mean "no timeout" — a slowloris
attack waits forever. A safe baseline:

| Timeout | Value | Why |
|---|---|---|
| `ReadTimeout` | 30s | Limits time to read full request |
| `WriteTimeout` | 30s | Limits time to write response |
| `IdleTimeout` | 120s | Closes idle keep-alive connections |
| `ReadHeaderTimeout` | 10s | Tighter than `ReadTimeout` for headers alone |

For long-running endpoints (uploads, streams), set timeouts on the
specific handler with `http.TimeoutHandler` or a per-route Chi middleware
rather than loosening the server-wide defaults.

## When to load a sibling skill

| Task | Skill |
|---|---|
| Database queries via sqlc | go-sql |
| Request-scoped slog with attrs from context | go-logging |
| Typed errors and status mapping | go-errors |
| Handler tests with `httptest` | go-testing |
| Per-request goroutines, errgroup | go-concurrency |
