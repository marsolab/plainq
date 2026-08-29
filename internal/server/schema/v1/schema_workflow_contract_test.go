package v1

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func readSchemaWorkflow(t *testing.T, filename string) string {
	t.Helper()

	_, testFilename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve schema workflow contract test path")
	}
	path := filepath.Join(filepath.Dir(testFilename), "../../../../.github/workflows", filename)
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	return string(contents)
}

func TestSchemaWorkflowsCoverGenerationInputs(t *testing.T) {
	t.Parallel()

	for _, filename := range []string{"schema-pr.yaml", "schema-release.yaml"} {
		t.Run(filename, func(t *testing.T) {
			workflow := readSchemaWorkflow(t, filename)
			for _, path := range []string{"'Makefile'", "'go.mod'", "'internal/server/schema/**'"} {
				if !strings.Contains(workflow, path) {
					t.Errorf("workflow does not trigger for %s", path)
				}
			}
		})
	}
}

func TestSchemaReleasePublishesOnlyForSchemaChanges(t *testing.T) {
	t.Parallel()

	workflow := readSchemaWorkflow(t, "schema-release.yaml")
	for _, contract := range []string{
		"fetch-depth: 0",
		"github.event.before",
		"github.sha",
		`git diff --quiet "$base" "$AFTER" -- schema`,
		"github.event_name == 'workflow_dispatch'",
		"needs.changes.outputs.schema_changed == 'true'",
		"needs.generated.result == 'success'",
		"needs.breaking.result == 'success'",
		"needs.lint.result == 'success'",
	} {
		if !strings.Contains(workflow, contract) {
			t.Errorf("release workflow is missing %q", contract)
		}
	}
}
