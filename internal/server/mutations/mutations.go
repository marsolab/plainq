package mutations

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
	"testing/fstest"
)

var (
	//go:embed storage/sqlite/*.sql
	sqliteStorage embed.FS

	//go:embed storage/postgres/*.sql
	postgresStorage embed.FS

	//go:embed telemetry/*.sql
	telemetry embed.FS
)

// SqliteStorageMutations returns the embedded SQLite storage migrations.
func SqliteStorageMutations() fs.FS {
	d, err := fs.Sub(sqliteStorage, "storage/sqlite")
	if err != nil {
		panic(err)
	}

	return d
}

// PostgresStorageMutations returns the embedded PostgreSQL storage migrations.
func PostgresStorageMutations() fs.FS {
	d, err := fs.Sub(postgresStorage, "storage/postgres")
	if err != nil {
		panic(err)
	}

	return d
}

// TelemetryMutation returns all embedded telemetry migration files.
func TelemetryMutation() fs.FS {
	d, err := fs.Sub(telemetry, "telemetry")
	if err != nil {
		panic(err)
	}

	return d
}

// StorageMutation is one validated, numerically versioned migration.
type StorageMutation struct {
	Name    string
	Version int
	Changes []byte
}

// ValidatedStorageMutations loads migrations after proving that their numeric
// filename prefixes are unique, contiguous, and lexically monotonic.
//
//nolint:cyclop,wsl_v5 // Every invalid filename/version state has a distinct diagnostic.
func ValidatedStorageMutations(migrations fs.FS) ([]StorageMutation, error) {
	entries, err := fs.ReadDir(migrations, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("no schema migrations found")
	}

	versions := make([]int, 0, len(entries))
	seen := make(map[int]string, len(entries))
	validated := make([]StorageMutation, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			return nil, fmt.Errorf("non-numeric migration version in %q", entry.Name())
		}

		separator := strings.IndexByte(entry.Name(), '_')
		if separator <= 0 {
			return nil, fmt.Errorf("non-numeric migration version in %q", entry.Name())
		}

		version, parseErr := strconv.Atoi(entry.Name()[:separator])
		if parseErr != nil || version <= 0 {
			return nil, fmt.Errorf("non-numeric migration version in %q", entry.Name())
		}
		if previous, ok := seen[version]; ok {
			return nil, fmt.Errorf(
				"duplicate migration version %d in %q and %q",
				version, previous, entry.Name(),
			)
		}

		changes, readErr := fs.ReadFile(migrations, entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), readErr)
		}

		seen[version] = entry.Name()
		versions = append(versions, version)
		validated = append(validated, StorageMutation{
			Name: entry.Name(), Version: version, Changes: changes,
		})
	}

	for index := 1; index < len(versions); index++ {
		if versions[index] < versions[index-1] {
			return nil, fmt.Errorf(
				"non-monotonic migration versions: %d follows %d",
				versions[index], versions[index-1],
			)
		}
	}

	for index, version := range versions {
		expected := index + 1
		if version != expected {
			return nil, fmt.Errorf("missing migration version %d before version %d", expected, version)
		}
	}

	return validated, nil
}

// ValidatedStorageFS copies a validated migration set into a lexically sorted
// filesystem for litekit. Its 1-based positions are therefore the parsed
// numeric versions.
func ValidatedStorageFS(migrations fs.FS) (fs.FS, error) {
	records, err := ValidatedStorageMutations(migrations)
	if err != nil {
		return nil, err
	}

	validated := make(fstest.MapFS, len(records))
	for _, record := range records {
		validated[record.Name] = &fstest.MapFile{Data: record.Changes}
	}

	return validated, nil
}
