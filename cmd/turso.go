package main

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// tursoSchemes lists the URL schemes PlainQ accepts for a Turso database.
// "libsql" is the scheme Turso hands out; it upgrades to HTTPS on connect.
//
// The libSQL driver also understands "ws"/"wss" and "file", which PlainQ
// deliberately rejects:
//
//   - Over websockets the driver speaks Hrana v1, which does not carry column
//     declared types. PlainQ stores timestamps in TIMESTAMP columns and scans
//     them into time.Time, a conversion the driver can only make when it knows
//     the declared type. Every timestamp read would fail.
//   - A "file" URL is a local SQLite database, which is what the sqlite
//     storage driver already does, with WAL tuning and Litestream backups.
var tursoSchemes = []string{"libsql", "https", "http"}

// tursoDSN is a validated Turso connection target: a URL with no credentials
// in it, and the token to present separately.
type tursoDSN struct {
	url       string
	authToken string
}

// parseTursoDSN validates the configured Turso URL and resolves the auth token
// to use with it.
//
// The libSQL driver refuses a URL that carries the token as a query parameter
// and wants it passed as a connector option instead. Turso's dashboard and CLI
// hand out URLs in both shapes, so a token found in the URL is lifted out here
// rather than rejected: an explicitly configured token wins, and the returned
// URL is always clean of credentials, which keeps them out of log lines.
func parseTursoDSN(rawURL, authToken string) (tursoDSN, error) {
	if rawURL == "" {
		return tursoDSN{}, errors.New("storage.turso.url must be set when storage.driver=turso")
	}

	parsed, parseErr := url.Parse(rawURL)
	if parseErr != nil {
		return tursoDSN{}, fmt.Errorf("parse turso url: %w", parseErr)
	}

	if parsed.Scheme == "file" {
		return tursoDSN{}, errors.New("file:// URLs are local SQLite databases: use storage.driver=sqlite with storage.path")
	}

	if !slices.Contains(tursoSchemes, parsed.Scheme) {
		return tursoDSN{}, fmt.Errorf("unsupported turso url scheme %q (want one of: %s)",
			parsed.Scheme, strings.Join(tursoSchemes, ", "),
		)
	}

	query := parsed.Query()

	// The driver accepts the token under any of these names when it is part of
	// the URL. Pull all of them out so none reaches the driver.
	for _, param := range []string{"authToken", "auth_token", "jwt"} {
		embedded := query.Get(param)

		if authToken == "" {
			authToken = embedded
		}

		query.Del(param)
	}

	parsed.RawQuery = query.Encode()

	return tursoDSN{url: parsed.String(), authToken: authToken}, nil
}
