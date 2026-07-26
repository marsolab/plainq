// Package manifests_test keeps the shipped example manifests honest.
//
// The samples under deploy/operator/samples are what people copy first, and
// they were written alongside the design rather than against the Go types. A
// strict decode is the cheapest way to guarantee they never drift: an unknown
// or misspelled field fails here rather than at someone's kubectl apply.
package manifests_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	plainqv1alpha1 "github.com/marsolab/plainq/operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

// samplesDir is the shipped example directory, relative to this package.
const samplesDir = "../../../deploy/operator/samples"

// typeFor returns an empty object of the right kind, or nil for kinds this
// operator does not own (plain Secrets and PVCs appear in the samples too).
func typeFor(kind string) runtime.Object {
	switch kind {
	case "PlainQ":
		return &plainqv1alpha1.PlainQ{}
	case "PlainQQueue":
		return &plainqv1alpha1.PlainQQueue{}
	case "PlainQTopic":
		return &plainqv1alpha1.PlainQTopic{}
	case "PlainQAccount":
		return &plainqv1alpha1.PlainQAccount{}
	case "PlainQBackupPolicy":
		return &plainqv1alpha1.PlainQBackupPolicy{}
	case "PlainQBackup":
		return &plainqv1alpha1.PlainQBackup{}
	case "PlainQRestore":
		return &plainqv1alpha1.PlainQRestore{}
	}

	return nil
}

// header is the minimum needed to route a document to its type.
type header struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Metadata   struct {
		Name string `json:"name"`
	} `json:"metadata"`
}

func TestShippedSamplesDecodeStrictly(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(samplesDir)
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}

	// Counted across parallel subtests, and asserted in Cleanup so the check
	// runs after they finish rather than while they are still starting.
	var checked atomic.Int64

	t.Cleanup(func() {
		if checked.Load() == 0 {
			t.Errorf("no sample manifests were checked; %s is probably wrong", samplesDir)
		}
	})

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(filepath.Join(samplesDir, entry.Name()))
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			for i, doc := range splitDocuments(raw) {
				var head header
				if err := yaml.Unmarshal(doc, &head); err != nil {
					t.Fatalf("document %d: parse header: %v", i, err)
				}

				if !strings.HasPrefix(head.APIVersion, plainqv1alpha1.GroupVersion.Group+"/") {
					// A Secret or a PVC the sample sets up alongside ours.
					continue
				}

				obj := typeFor(head.Kind)
				if obj == nil {
					t.Errorf("document %d: unknown kind %q in group %s",
						i, head.Kind, plainqv1alpha1.GroupVersion.Group)

					continue
				}

				// Strict: an unknown field is an error, which is exactly the
				// drift this test exists to catch.
				if err := yaml.UnmarshalStrict(doc, obj); err != nil {
					t.Errorf("%s %q: %v", head.Kind, head.Metadata.Name, err)
				}

				checked.Add(1)
			}
		})
	}

}

// splitDocuments splits a multi-document YAML file.
func splitDocuments(raw []byte) [][]byte {
	var docs [][]byte

	for _, part := range bytes.Split(raw, []byte("\n---")) {
		if len(bytes.TrimSpace(part)) > 0 {
			docs = append(docs, part)
		}
	}

	return docs
}

func TestSamplesSurviveDefaulting(t *testing.T) {
	t.Parallel()

	// Defaulting runs on every object at admission and again at render time.
	// It has to be idempotent, or the second pass would look like a change
	// and roll the pods on every reconcile.
	entries, err := os.ReadDir(samplesDir)
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(samplesDir, entry.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}

		for _, doc := range splitDocuments(raw) {
			var head header
			if err := yaml.Unmarshal(doc, &head); err != nil || head.Kind != "PlainQ" {
				continue
			}

			var pq plainqv1alpha1.PlainQ
			if err := yaml.UnmarshalStrict(doc, &pq); err != nil {
				t.Fatalf("%s: %v", head.Metadata.Name, err)
			}

			pq.Spec.ApplyDefaults()
			once := pq.DeepCopy()

			pq.Spec.ApplyDefaults()

			if !equalJSON(t, once, &pq) {
				t.Errorf("%s: defaulting is not idempotent", head.Metadata.Name)
			}
		}
	}
}

func equalJSON(t *testing.T, a, b any) bool {
	t.Helper()

	left, err := yaml.Marshal(a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	right, err := yaml.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return bytes.Equal(left, right)
}
