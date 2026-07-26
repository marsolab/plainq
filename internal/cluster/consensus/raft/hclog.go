package raft

import (
	"io"
	"log"
	"log/slog"

	hclog "github.com/hashicorp/go-hclog"
)

// hclogAdapter routes hashicorp/raft's logging into the server's slog handler,
// so a cluster's diagnostics land in the same stream, with the same format, as
// everything else the server says.
type hclogAdapter struct {
	logger *slog.Logger
	name   string
	level  hclog.Level
}

// Compilation time check that hclogAdapter implements hclog.Logger.
var _ hclog.Logger = (*hclogAdapter)(nil)

func newHCLogAdapter(logger *slog.Logger, name string) hclog.Logger {
	return &hclogAdapter{logger: logger, name: name, level: hclog.Debug}
}

func (a *hclogAdapter) Log(level hclog.Level, msg string, args ...any) {
	switch level {
	case hclog.Error:
		a.Error(msg, args...)

	case hclog.Warn:
		a.Warn(msg, args...)

	case hclog.Info:
		a.Info(msg, args...)

	case hclog.Debug, hclog.Trace, hclog.NoLevel, hclog.Off:
		a.Debug(msg, args...)

	default:
		a.Debug(msg, args...)
	}
}

// Trace maps onto debug: slog has no trace level, and raft's trace output is
// per-heartbeat.
func (a *hclogAdapter) Trace(msg string, args ...any) {
	a.logger.Debug(a.prefix(msg), a.attrs(args)...)
}

func (a *hclogAdapter) Debug(msg string, args ...any) {
	a.logger.Debug(a.prefix(msg), a.attrs(args)...)
}
func (a *hclogAdapter) Info(msg string, args ...any) { a.logger.Info(a.prefix(msg), a.attrs(args)...) }
func (a *hclogAdapter) Warn(msg string, args ...any) { a.logger.Warn(a.prefix(msg), a.attrs(args)...) }
func (a *hclogAdapter) Error(msg string, args ...any) {
	a.logger.Error(a.prefix(msg), a.attrs(args)...)
}

func (a *hclogAdapter) IsTrace() bool { return a.logger.Enabled(nil, slog.LevelDebug) } //nolint:staticcheck // hclog has no context.
func (a *hclogAdapter) IsDebug() bool { return a.logger.Enabled(nil, slog.LevelDebug) } //nolint:staticcheck // same.
func (a *hclogAdapter) IsInfo() bool  { return a.logger.Enabled(nil, slog.LevelInfo) }  //nolint:staticcheck // same.
func (a *hclogAdapter) IsWarn() bool  { return a.logger.Enabled(nil, slog.LevelWarn) }  //nolint:staticcheck // same.
func (a *hclogAdapter) IsError() bool { return a.logger.Enabled(nil, slog.LevelError) } //nolint:staticcheck // same.

func (a *hclogAdapter) ImpliedArgs() []any { return nil }

func (a *hclogAdapter) With(args ...any) hclog.Logger {
	return &hclogAdapter{logger: a.logger.With(a.attrs(args)...), name: a.name, level: a.level}
}

func (a *hclogAdapter) Name() string { return a.name }

func (a *hclogAdapter) Named(name string) hclog.Logger {
	next := name
	if a.name != "" {
		next = a.name + "." + name
	}

	return &hclogAdapter{logger: a.logger, name: next, level: a.level}
}

func (a *hclogAdapter) ResetNamed(name string) hclog.Logger {
	return &hclogAdapter{logger: a.logger, name: name, level: a.level}
}

func (a *hclogAdapter) SetLevel(level hclog.Level) { a.level = level }

func (a *hclogAdapter) GetLevel() hclog.Level { return a.level }

func (a *hclogAdapter) StandardLogger(*hclog.StandardLoggerOptions) *log.Logger {
	return log.New(a.StandardWriter(nil), "", 0)
}

func (a *hclogAdapter) StandardWriter(*hclog.StandardLoggerOptions) io.Writer {
	return &hclogWriter{adapter: a}
}

func (a *hclogAdapter) prefix(msg string) string {
	if a.name == "" {
		return msg
	}

	return a.name + ": " + msg
}

// attrs converts hclog's alternating key/value arguments into slog arguments.
// An odd trailing argument would make slog complain about a dangling key, so
// it is given one.
func (a *hclogAdapter) attrs(args []any) []any {
	if len(args)%2 == 0 {
		return args
	}

	return append(args[:len(args):len(args)], "!BADKEY")
}

// hclogWriter lets callers that want an io.Writer log through the adapter.
type hclogWriter struct{ adapter *hclogAdapter }

func (w *hclogWriter) Write(p []byte) (int, error) {
	w.adapter.Debug(string(p))

	return len(p), nil
}
