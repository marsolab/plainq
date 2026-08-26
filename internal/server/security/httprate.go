package security

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
)

// HTTPSourceIP returns the socket peer address. Proxy headers are deliberately
// ignored here because accepting an untrusted X-Forwarded-For would let a
// caller choose a fresh rate-limit bucket on every request.
func HTTPSourceIP(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil && host != "" {
		return host
	}

	return request.RemoteAddr
}

// OpaqueRateKey hashes potentially sensitive account identifiers before they
// are retained in the limiter's bounded in-memory map.
func OpaqueRateKey(namespace, value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	digest := sha256.Sum256([]byte(namespace + "\x00" + normalized))

	return namespace + ":" + hex.EncodeToString(digest[:])
}
