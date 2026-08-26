package litestore

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"testing"
)

type scriptedSweeper struct {
	results []error
	seen    []string
}

func (s *scriptedSweeper) Sweep(_ context.Context, queueID string) error {
	s.seen = append(s.seen, queueID)
	err := s.results[0]
	s.results = s.results[1:]

	return err
}

func TestGCContinuesAfterOneQueueFails(t *testing.T) {
	broken := errors.New("broken queue")
	sweeper := &scriptedSweeper{results: []error{broken, nil}}

	err := runSweepBatch(context.Background(), []string{"broken", "healthy"}, sweeper.Sweep, slog.Default())
	if !errors.Is(err, broken) {
		t.Fatalf("sweep error = %v, want broken queue", err)
	}

	if !reflect.DeepEqual(sweeper.seen, []string{"broken", "healthy"}) {
		t.Fatalf("swept queues = %v, want [broken healthy]", sweeper.seen)
	}
}
