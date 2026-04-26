package telemetry

import (
	"errors"
	"slices"
	"strings"
	"time"
)

// Metric represents an event at some point of time
// that holds an information about some observed value.
type Metric struct {
	Name   string      `json:"name"`
	Labels Labels      `json:"labels,omitempty"`
	Values []Datapoint `json:"values,omitempty"`
}

// Datapoint represents Metric datapoint.
// Holds timestamp and a metric value for it.
type Datapoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}

// Label is a pair of key/value metadata that is attached to a Metric.
type Label struct{ Key, Value string }

// Labels represents a collection of Label pairs attached to a Metric.
// It provides methods for converting labels to a map, string representation, and extracting the queue ID.
type Labels []Label

func (l Labels) Map() map[string]string {
	m := make(map[string]string, len(l))

	for _, label := range l {
		m[label.Key] = label.Value
	}

	return m
}

func (l Labels) String() string {
	var sb strings.Builder

	for i, label := range l {
		sb.WriteString(label.Key)
		_ = sb.WriteByte('=') //nolint:errcheck // strings.Builder.WriteByte never returns an error.
		sb.WriteString(label.Value)

		if i+1 != len(l) {
			_ = sb.WriteByte(',') //nolint:errcheck // strings.Builder.WriteByte never returns an error.
		}
	}

	return strings.TrimSpace(sb.String())
}

func LabelsFromString(s string) (Labels, error) {
	if s == "" {
		return make(Labels, 0), nil
	}

	kvs := strings.Split(s, ",")
	if len(kvs) == 0 {
		return nil, errors.New("invalid labels format")
	}

	labels := make([]Label, 0, len(kvs))
	for _, kv := range kvs {
		parts := strings.Split(kv, "=")

		if len(parts) != 2 {
			return nil, errors.New("invalid labels format")
		}

		labels = append(labels, Label{
			Key:   parts[0],
			Value: parts[1],
		})
	}

	return labels, nil
}

func (l Labels) QueueID() string {
	idx := slices.IndexFunc[Labels](l, func(l Label) bool { return l.Key == "queue" })
	if idx < 0 {
		return ""
	}

	return l[idx].Value
}
