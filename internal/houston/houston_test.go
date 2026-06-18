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

	want := map[string]bool{
		"_astro": true, "favicon.svg": true, "index.html": true,
		"login": true, "queue": true, "settings": true, "signup": true, "users": true,
	}
	for _, e := range entries {
		delete(want, e.Name())
	}
	if len(want) > 0 {
		t.Fatalf("missing from bundle: %v", want)
	}
}
