# Idiomatic Go: Patterns, Libraries, Context, and Configuration

> Target: Go 1.22+ (most guidance applies back to 1.20).  
> Audience: Engineers building HTTP services, CLIs, workers in Go.

## Table of Contents
- Purpose, Prereqs, Tooling
- Project Layout and Module Hygiene
- Idioms
  - Naming and Formatting
  - Error Handling
  - Interfaces and API Design
  - Concurrency and Synchronization
  - Testing and Logging
- Context (Deep Dive)
- Configuration (Deep Dive)
- Popular Libraries (Curated)
- Practical Templates
- References

---

## Purpose, Prereqs, Tooling
- Install Go 1.22+. Use `gofmt`/`goimports` automatically via editor.  
- Recommended tooling: `govulncheck`, `staticcheck`, `golangci-lint`, `go test -race`.  
- Principles: simplicity, small interfaces, explicit errors, zero-value usability, composition over inheritance.

## Project Layout and Module Hygiene
- Use modules (`go.mod`) per repo. Keep `module` path stable.
- Common structure:
  - `cmd/<app>/main.go` entrypoints
  - `internal/...` for non-public packages
  - `pkg/...` for optional public packages (use sparingly)
  - `internal/app/...` for app wiring; domain packages under `internal/`
- Guidance:
  - Avoid stutter in package names (e.g., `logger.Logger` → `log.Logger`).
  - Keep package APIs small; hide internals.
  - Prefer one responsibility per package.
  - Use `go:generate` and `//go:embed` where appropriate.

## Idioms

### Naming and Formatting
- Package names: short, lower-case, no underscores (e.g., `store`, `httpx`).
- Exported identifiers start with capital letter; avoid stutter: `bytes.Buffer` not `bytes.ByteBuffer`.
- Receivers: short, meaningful (e.g., `r *Reader`, `s *Server`).
- Prefer `time.Duration` for intervals; pass in base units (e.g., `500 * time.Millisecond`).

### Error Handling
- Return errors; do not use exceptions. Reserve `panic` for truly unrecoverable programmer errors.
- Wrap with `%w` to preserve cause; use `errors.Is/As` for checks:
  ```go
  if err != nil {
      return fmt.Errorf("open config: %w", err)
  }
  ```
- Prefer typed errors over exported sentinels when extra data helps handling. Keep error messages lowercase without trailing punctuation.
- Guard clauses > deep nesting.

### Interfaces and API Design
- Accept interfaces, return concrete types. Keep interfaces small (1–3 methods).  
  Example: depend on `io.Reader`/`io.Writer` instead of custom large interfaces.
- Zero-value types should be usable when possible. Provide constructors only to enforce invariants.
- Use functional options for configuration instead of long parameter lists.

### Concurrency and Synchronization
- Start goroutines intentionally; stop them deterministically. Avoid leaks by binding to `context.Context`.
- Use channels for synchronization/communication, but prefer `x/sync/errgroup` for orchestration.
- Prefer `sync.Mutex` to channel-based state unless channels model your workflow.
- Avoid per-operation goroutines when batching or worker pools suffice.

### Testing and Logging
- Table-driven tests with subtests; fuzz tests for parsers; benchmarks for hot paths.
- Use the race detector in CI (`go test -race ./...`).
- Prefer structured logging. Standard library `log/slog` is a solid default.

---

## Context (Deep Dive)

### Do
- Pass `context.Context` as the first parameter in request-scoped functions: `func (s *Svc) Get(ctx context.Context, id string) ...`.
- Use `WithTimeout/WithDeadline` to bound work; cancel on shutdown.
- Use typed keys for values you must thread; keep usage rare and focused (e.g., request ID).
- Derive from incoming contexts (`req.Context()`) in servers and propagate downstream.

### Don’t
- Don’t store contexts in structs or as fields.
- Don’t pass `nil` contexts; use `context.Background()` or `context.TODO()`.
- Don’t stuff optional parameters into context; use function parameters.

### HTTP Handler example
```go
package handler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Store interface {
	FindUser(ctx context.Context, id string) (User, error)
}

type User struct {
	ID   string
	Name string
}

type Server struct {
	DB *sql.DB
	St Store
}

func (s *Server) getUser(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	id := r.URL.Query().Get("id")
	u, err := s.St.FindUser(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, fmt.Sprintf("error: %v", err), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Hello %s", u.Name)
}
```

### Graceful shutdown in `main`
```go
srv := &http.Server{Addr: ":8080", Handler: mux}
go func() {
	_ = srv.ListenAndServe()
}()

ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
defer stop()

<-ctx.Done()
shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
_ = srv.Shutdown(shutdownCtx)
```

### `http.Client` timeouts
- Prefer per-request contexts and a sane `http.Client{Timeout: ...}` default.

---

## Configuration (Deep Dive)

### Goals
- Follow 12‑factor: config via env/flags; file only for convenience.  
- Single `Config` struct with validation; inject where needed.  
- Clear precedence: flags > env > file > defaults.

### Standard library baseline
```go
type Config struct {
	Addr          string        // HTTP bind address
	DBURL         string        // Postgres URL
	ShutdownGrace time.Duration // e.g., 5s
}

func (c *Config) Validate() error {
	if c.Addr == "" {
		return errors.New("addr is required")
	}
	if c.DBURL == "" {
		return errors.New("db url is required")
	}
	return nil
}
```

### Loading with flags + env (Koanf example)
```go
// go get github.com/knadh/koanf/v2
var k = koanf.New(".")

func LoadConfig() (Config, error) {
	_ = k.Load(confmap.Provider(map[string]interface{}{
		"addr":            ":8080",
		"shutdown_grace":  "5s",
	}, "."), nil)

	_ = k.Load(env.Provider("", ".", func(s string) string {
		return strings.ToLower(strings.ReplaceAll(s, "_", "."))
	}), nil)

	fset := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fset.String("addr", k.String("addr"), "HTTP bind address")
	fset.String("dburl", "", "Database URL")
	fset.Duration("shutdown_grace", k.Duration("shutdown_grace"), "Shutdown grace period")
	_ = fset.Parse(os.Args[1:])
	_ = k.Load(posflag.Provider(fset, ".", k), nil)

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return Config{}, err
	}
	return cfg, cfg.Validate()
}
```

### Secrets
- Prefer env vars or secret stores. Do not commit secrets.  
- In Kubernetes, mount secrets to files and read paths into config.  
- Consider per-env overlays (e.g., `APP_ENV=prod`) to select profiles.

### Functional options example
```go
type Client struct {
	baseURL string
	timeout time.Duration
	log     *slog.Logger
}

type Option func(*Client)

func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }
func WithLogger(l *slog.Logger) Option   { return func(c *Client) { c.log = l } }

func NewClient(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: baseURL,
		timeout: 5 * time.Second,
		log:     slog.Default(),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}
```

---

## Popular Libraries (Curated)

- HTTP/Routing: `net/http`, `go-chi/chi`, `gin-gonic/gin`, `labstack/echo`
  - chi: idiomatic, lightweight, composable middleware
  - gin/echo: batteries-included, faster onboarding
- Middleware helpers: `justinas/alice`, `go-chi/chi/middleware`
- Validation: `go-playground/validator`
- Logging: std `log/slog`, `uber-go/zap`, `rs/zerolog`
- Configuration: `spf13/viper`, `knadh/koanf`, `kelseyhightower/envconfig`, `joho/godotenv`
- DB:
  - std `database/sql`, Postgres: `jackc/pgx`
  - Query helpers: `jmoiron/sqlx`, codegen: `sqlc`
  - ORMs: `gorm`, schema-first: `ent`
- Migrations: `golang-migrate/migrate`
- Testing: `stretchr/testify`, `onsi/ginkgo` + `gomega`, `gavv/httpexpect`, `golang/mock`
- Concurrency utils: `golang.org/x/sync/errgroup`, `semaphore`
- Metrics/Tracing: Prometheus `client_golang`, OpenTelemetry (`go.opentelemetry.io/otel`)
- Messaging: `nats-io/nats.go`, `segmentio/kafka-go`, `rabbitmq/amqp091-go`
- Cache: `redis/go-redis/v9`
- Jobs/Scheduling: `robfig/cron/v3`
- WebSockets: `nhooyr/websocket`, `gorilla/websocket`
- Serialization: `encoding/json`, `json-iterator/go` (only when justified)
- Filesystems: `spf13/afero`
- CLI: `spf13/cobra`, `urfave/cli/v2`

---

## Practical Templates

### HTTP service skeleton (chi + slog + graceful shutdown)
```go
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	r := chi.NewRouter()
	r.Use(middleware.RequestID, middleware.RealIP, middleware.Recoverer)
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if !errors.Is(srv.ListenAndServe(), http.ErrServerClosed) {
			log.Error("server error")
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
```

### Worker skeleton (errgroup + context)
```go
g, ctx := errgroup.WithContext(context.Background())

jobs := make(chan Task, 128)
for i := 0; i < 4; i++ {
	i := i
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case t := <-jobs:
				if err := process(ctx, t); err != nil {
					return err
				}
			}
		}
	})
}

// feed jobs
g.Go(func() error {
	defer close(jobs)
	return produce(ctx, jobs)
})

if err := g.Wait(); err != nil {
	// handle error, trigger retry/backoff as needed
}
```

### CLI skeleton (cobra + config load)
```go
var rootCmd = &cobra.Command{
	Use:   "app",
	Short: "Example CLI",
}

func init() {
	rootCmd.PersistentFlags().String("config", "", "config file")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
```

---

## References
- Effective Go
- Go Modules, Workspaces
- Diagnostics: `govulncheck`, `pprof`, `trace`, race detector
- Concurrency patterns (Go blog), `x/sync/errgroup`
- OpenTelemetry for Go, Prometheus client
- SQL database best practices (`database/sql`, pgx)


