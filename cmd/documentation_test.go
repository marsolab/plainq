package main

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

func TestTopicCommandDocumentationMirrorsCanonicalHeadings(t *testing.T) {
	want := topicLeafPathsFromSchema(t)

	for _, name := range []string{
		"docs/guides/cli.md",
		"docs/reference/cli.md",
		"website/src/content/docs/docs/guides/cli.md",
		"website/src/content/docs/docs/reference/cli.md",
	} {
		t.Run(name, func(t *testing.T) {
			got := topicCommandHeadings(readDocumentationFile(t, name))
			td.Cmp(t, got, want, "topic command headings must mirror the six stable CLI leaves")
		})
	}
}

func TestTopicCommandDocumentationIncludesStableInputAndOutputContract(t *testing.T) {
	want := []string{
		"4 MiB",
		"deleted<TAB><topic-id>",
		"unsubscribed<TAB><subscription-id>",
	}

	for _, name := range []string{
		"docs/guides/cli.md",
		"docs/reference/cli.md",
		"website/src/content/docs/docs/guides/cli.md",
		"website/src/content/docs/docs/reference/cli.md",
	} {
		t.Run(name, func(t *testing.T) {
			content := readDocumentationFile(t, name)
			for _, contract := range want {
				if !strings.Contains(content, contract) {
					t.Errorf("%s is missing stable topic CLI contract %q", name, contract)
				}
			}
		})
	}
}

func TestTelemetryConfigurationDocumentationMirrorsDefaults(t *testing.T) {
	want := map[string]string{
		"--telemetry.enable":                    "true",
		"--telemetry.provider":                  "sqlite",
		"--telemetry.log.enable":                "false",
		"--telemetry.sqlite.collection.timeout": "10s",
		"--telemetry.sqlite.gc.timeout":         "10m",
		"--telemetry.sqlite.retention.period":   "336h",
		"--telemetry.prometheus.baseurl":        "",
	}

	for _, name := range []string{
		"docs/guides/configuration.md",
		"docs/reference/configuration.md",
		"website/src/content/docs/docs/guides/configuration.md",
		"website/src/content/docs/docs/reference/configuration.md",
	} {
		t.Run(name, func(t *testing.T) {
			got := telemetryDefaults(readDocumentationFile(t, name))
			td.Cmp(t, got, want, "telemetry defaults must mirror the stable server configuration")
		})
	}
}

func TestStablePubSubDocumentationHasNoExperimentalClaims(t *testing.T) {
	forbidden := []string{
		"experimental",
		"http-only",
		"http only",
		"no grpc/cli",
		"no grpc or cli",
		"no grpc, cli",
	}

	for _, name := range []string{
		"docs/guides/advanced.md",
		"docs/guides/troubleshooting.md",
		"docs/guides/grpc-api.md",
		"website/src/components/Usage.astro",
		"website/src/content/docs/docs/index.mdx",
	} {
		t.Run(name, func(t *testing.T) {
			content := strings.ToLower(readDocumentationFile(t, name))
			for _, claim := range forbidden {
				if strings.Contains(content, claim) {
					t.Errorf("%s still contains forbidden pre-stable claim %q", name, claim)
				}
			}
		})
	}
}

func documentationRoot(t *testing.T) string {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve documentation test source path")
	}

	return filepath.Clean(filepath.Join(filepath.Dir(filename), ".."))
}

func readDocumentationFile(t *testing.T, name string) string {
	t.Helper()

	content, err := os.ReadFile(filepath.Join(documentationRoot(t), filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return string(content)
}

func topicLeafPathsFromSchema(t *testing.T) []string {
	t.Helper()

	surface, err := buildSchema(testRoot(t), schemaTargetCLI)
	if err != nil {
		t.Fatalf("build CLI schema: %v", err)
	}
	if surface.CLI == nil {
		t.Fatal("CLI schema is absent")
	}

	for _, command := range surface.CLI.Commands {
		if command.Path != "plainq topic" {
			continue
		}

		paths := make([]string, 0, len(command.Subcommands))
		for _, leaf := range command.Subcommands {
			paths = append(paths, leaf.Path)
		}
		sort.Strings(paths)

		return paths
	}

	t.Fatal("plainq topic command is absent from the CLI schema")

	return nil
}

func topicCommandHeadings(content string) []string {
	wantedLeaves := map[string]bool{
		"list": true, "create": true, "delete": true,
		"subscribe": true, "unsubscribe": true, "publish": true,
	}
	commands := make(map[string]bool, len(wantedLeaves))

	for line := range strings.SplitSeq(content, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "### ") {
			continue
		}

		normalized := strings.ToLower(strings.NewReplacer("`", "", "*", "").Replace(line))
		fields := strings.Fields(normalized)
		for i := range fields {
			if fields[i] != "topic" || i+1 >= len(fields) {
				continue
			}

			leaf := strings.Trim(fields[i+1], "()[]{}<>:—–-,")
			if wantedLeaves[leaf] {
				commands["plainq topic "+leaf] = true
			}
		}
	}

	out := make([]string, 0, len(commands))
	for command := range commands {
		out = append(out, command)
	}
	sort.Strings(out)

	return out
}

func telemetryDefaults(content string) map[string]string {
	defaults := make(map[string]string)

	for line := range strings.SplitSeq(content, "\n") {
		cells := strings.Split(line, "|")
		if len(cells) < 4 {
			continue
		}

		flag := normalizeDocumentationCell(cells[1])
		flag = strings.TrimLeft(flag, "-")
		if !strings.HasPrefix(flag, "telemetry.") {
			continue
		}

		value := strings.ToLower(normalizeDocumentationCell(cells[2]))
		switch value {
		case "(empty)", "empty", "—", "-":
			value = ""
		}
		defaults["--"+flag] = value
	}

	return defaults
}

func normalizeDocumentationCell(value string) string {
	return strings.TrimSpace(strings.NewReplacer("`", "", "*", "", "_", "").Replace(value))
}
