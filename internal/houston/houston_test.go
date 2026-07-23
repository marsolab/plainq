package houston

import (
	"io/fs"
	"testing"
)

func TestBundle(t *testing.T) {
	b := Bundle()

	if _, err := fs.Stat(b, "index.html"); err != nil {
		t.Fatalf("index.html not in bundle: %v", err)
	}

	entries, err := fs.ReadDir(b, ".")
	if err != nil {
		t.Fatalf("read root: %v", err)
	}

	// The routes Houston ships. "settings" and "users" were folded into
	// "access" and "system" by the redesign; "telemetry" carries the Metrics
	// surface because the server reserves /metrics for Prometheus.
	want := map[string]bool{
		"_astro": true, "favicon.svg": true, "index.html": true, "404.html": true,
		"500.html": true, "access": true, "login": true, "queue": true,
		"pubsub": true, "setup": true, "signup": true, "system": true,
		"telemetry": true,
	}
	for _, e := range entries {
		delete(want, e.Name())
	}
	if len(want) > 0 {
		t.Fatalf("missing from bundle: %v", want)
	}
}
