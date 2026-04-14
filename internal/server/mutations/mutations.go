package mutations

import (
	"embed"
	"io/fs"
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
