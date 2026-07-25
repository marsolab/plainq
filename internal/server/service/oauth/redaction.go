package oauth

import (
	"sort"
	"strings"
	"time"
)

// secretConfigMarkers are the substrings that make a provider configuration key
// credential material.
//
// The rule is a denylist on purpose: a provider configuration is an open string
// map, so an allowlist would silently drop the issuer or audience of a provider
// type nobody anticipated, while a missed denylist entry is caught by the fact
// that every response also states which keys it withheld.
var secretConfigMarkers = []string{
	"secret",
	"password",
	"passwd",
	"private",
	"credential",
	"token",
	"jwk", // Private JWK sets are key material, unlike a jwks_url.
}

// IsSecretConfigKey reports whether a provider configuration key holds
// credential material that must never leave the server.
func IsSecretConfigKey(key string) bool {
	lower := strings.ToLower(key)

	// A URL pointing at a key set is a public address, not a secret; the
	// provider publishes it. Excluding it keeps the field usable in the UI.
	if strings.Contains(lower, "url") || strings.Contains(lower, "uri") {
		return false
	}

	for _, marker := range secretConfigMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// PublicProvider is a Provider with credential material removed. Every handler
// that answers with a provider answers with this type, so there is one place
// where a secret could leak and it is the place that removes them.
type PublicProvider struct {
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	OrgID        string `json:"org_id,omitempty"`

	// Config carries only the keys that are safe to show. A redacted key is
	// dropped entirely rather than replaced with a mask: a masked value invites
	// a copy button that yields bullets, and it cannot be told apart from a
	// provider genuinely configured with the string "••••••".
	Config map[string]string `json:"config"`

	// RedactedKeys names the configuration keys that exist on the server and
	// were withheld. It is what lets a client say "a client secret is set"
	// without ever holding one.
	RedactedKeys []string `json:"redacted_keys"`

	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Public projects a provider onto its secret-safe shape.
func (p Provider) Public() PublicProvider {
	safe := PublicProvider{
		ProviderID:   p.ProviderID,
		ProviderName: p.ProviderName,
		OrgID:        p.OrgID,
		Config:       make(map[string]string, len(p.Config)),
		RedactedKeys: []string{},
		IsActive:     p.IsActive,
		CreatedAt:    p.CreatedAt,
		UpdatedAt:    p.UpdatedAt,
	}

	for key, value := range p.Config {
		if IsSecretConfigKey(key) {
			safe.RedactedKeys = append(safe.RedactedKeys, key)

			continue
		}

		safe.Config[key] = value
	}

	// Map iteration order is random; a response whose key list reshuffles
	// between identical requests looks like a change that never happened.
	sort.Strings(safe.RedactedKeys)

	return safe
}

// PublicProviders projects a slice of providers, preserving order.
func PublicProviders(providers []Provider) []PublicProvider {
	safe := make([]PublicProvider, 0, len(providers))
	for _, provider := range providers {
		safe = append(safe, provider.Public())
	}

	return safe
}

// MergeConfig computes the configuration an update should store.
//
// A client never receives the stored secrets, so it cannot send them back. The
// rule that keeps an update from silently erasing them: the request replaces
// the configuration outright, except that a secret key the request does not
// mention keeps its stored value. Sending a secret key with an empty value is
// how a caller deliberately clears one — that is a real write, not an omission.
func MergeConfig(stored, requested map[string]string) map[string]string {
	merged := make(map[string]string, len(stored)+len(requested))

	for key, value := range requested {
		merged[key] = value
	}

	for key, value := range stored {
		if !IsSecretConfigKey(key) {
			continue
		}

		if _, sent := requested[key]; !sent {
			merged[key] = value
		}
	}

	return merged
}
