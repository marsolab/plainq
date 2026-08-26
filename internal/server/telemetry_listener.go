package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marsolab/plainq/internal/server/config"
	"github.com/marsolab/plainq/internal/server/service/telemetry/collector"
)

type telemetryCollectorSettings struct {
	collectionInterval time.Duration
	cleanupInterval    time.Duration
	retentionPeriod    time.Duration
}

type telemetryCollectorFactory func(
	store *collector.SQLiteStore,
	logger *slog.Logger,
	settings telemetryCollectorSettings,
) *collector.Collector

func newTelemetryCollector(
	store *collector.SQLiteStore,
	logger *slog.Logger,
	settings telemetryCollectorSettings,
) *collector.Collector {
	return collector.New(
		store,
		collector.WithLogger(logger),
		collector.WithCollectionInterval(settings.collectionInterval),
		collector.WithCleanupInterval(settings.cleanupInterval),
		collector.WithRetentionPeriod(settings.retentionPeriod),
	)
}

type telemetryWorker interface {
	Start(ctx context.Context)
	Stop()
}

type telemetryListener struct {
	worker telemetryWorker
}

func (l *telemetryListener) Serve(ctx context.Context) error {
	l.worker.Start(ctx)
	defer l.worker.Stop()

	<-ctx.Done()

	return nil
}

// ValidateTelemetryConfig rejects invalid worker grids before any telemetry
// database is opened.
func ValidateTelemetryConfig(cfg config.Config) error {
	if !cfg.TelemetryEnabled {
		return nil
	}

	collection := cfg.TelemetryLiteScrapeTimeout
	if collection <= 0 {
		return errors.New("telemetry collection interval must be positive")
	}

	if cfg.TelemetryLiteGCTimeout <= 0 {
		return errors.New("telemetry cleanup interval must be positive")
	}

	if collection < time.Millisecond {
		return errors.New("telemetry collection interval must be at least one millisecond")
	}

	if collection%time.Millisecond != 0 {
		return errors.New("telemetry collection interval must use whole milliseconds")
	}

	if time.Minute%collection != 0 {
		return fmt.Errorf("telemetry collection interval %s must divide one minute exactly", collection)
	}

	if cfg.TelemetryLiteRetentionPeriod < 24*time.Hour {
		return errors.New("telemetry retention period must be at least twenty-four hours")
	}

	return nil
}

func validateTelemetryConfig(cfg config.Config) error { return ValidateTelemetryConfig(cfg) }
