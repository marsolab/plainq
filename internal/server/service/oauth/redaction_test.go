package oauth

import (
	"encoding/json"
	"testing"

	"github.com/maxatome/go-testdeep/td"
)

func TestIsSecretConfigKey(t *testing.T) {
	secret := []string{
		"client_secret",
		"clientSecret",
		"CLIENT_SECRET",
		"password",
		"admin_passwd",
		"private_key",
		"api_credential",
		"refresh_token",
		"signing_jwk",
	}

	for _, key := range secret {
		td.Cmp(t, IsSecretConfigKey(key), true, "%q holds credential material", key)
	}

	public := []string{
		"issuer",
		"client_id",
		"domain",
		"audience",
		"scope",
		"callback_url",
		// A key set's address is published by the provider; withholding it
		// would hide configuration without protecting anything.
		"jwks_url",
		"token_endpoint_uri",
	}

	for _, key := range public {
		td.Cmp(t, IsSecretConfigKey(key), false, "%q is not credential material", key)
	}
}

func TestProviderPublicDropsSecretsEntirely(t *testing.T) {
	provider := Provider{
		ProviderID:   "idp-1",
		ProviderName: "kinde",
		Config: map[string]string{
			"issuer":        "https://acme.kinde.com",
			"client_id":     "kn_client_8f3a",
			"client_secret": "super-secret",
			"private_key":   "-----BEGIN PRIVATE KEY-----",
		},
		IsActive: true,
	}

	safe := provider.Public()

	td.Cmp(t, safe.Config, map[string]string{
		"issuer":    "https://acme.kinde.com",
		"client_id": "kn_client_8f3a",
	})
	td.Cmp(t, safe.RedactedKeys, []string{"client_secret", "private_key"},
		"withheld keys are named, and in a stable order")

	// A mask would be a value: it can be copied, and it cannot be told apart
	// from a provider genuinely configured with that string.
	encoded, err := json.Marshal(safe)
	td.Require(t).CmpNoError(err, "marshal provider")
	td.CmpNot(t, string(encoded), td.Contains("super-secret"))
	td.CmpNot(t, string(encoded), td.Contains("•"))
}

func TestProviderPublicKeepsEmptyCollectionsPresent(t *testing.T) {
	safe := Provider{ProviderID: "idp-1", ProviderName: "oidc"}.Public()

	encoded, err := json.Marshal(safe)
	td.Require(t).CmpNoError(err, "marshal provider")

	// A null config or a null key list would read as "unknown" in a client
	// that has to tell "no secrets stored" from "not told".
	td.Cmp(t, string(encoded), td.Contains(`"config":{}`))
	td.Cmp(t, string(encoded), td.Contains(`"redacted_keys":[]`))
}

func TestMergeConfigKeepsUnmentionedSecrets(t *testing.T) {
	stored := map[string]string{
		"issuer":        "https://acme.kinde.com",
		"client_id":     "old-client",
		"client_secret": "stored-secret",
	}

	t.Run("an update that omits the secret keeps it", func(t *testing.T) {
		merged := MergeConfig(stored, map[string]string{
			"issuer":    "https://acme.kinde.com",
			"client_id": "new-client",
		})

		td.Cmp(t, merged, map[string]string{
			"issuer":        "https://acme.kinde.com",
			"client_id":     "new-client",
			"client_secret": "stored-secret",
		})
	})

	t.Run("an update that sends the secret replaces it", func(t *testing.T) {
		merged := MergeConfig(stored, map[string]string{"client_secret": "rotated"})

		td.Cmp(t, merged["client_secret"], "rotated")
	})

	t.Run("an empty secret clears it, because that is a real write", func(t *testing.T) {
		merged := MergeConfig(stored, map[string]string{"client_secret": ""})

		td.Cmp(t, merged["client_secret"], "")
	})

	t.Run("a public key the update omits is dropped", func(t *testing.T) {
		merged := MergeConfig(stored, map[string]string{"client_secret": "rotated"})

		_, present := merged["issuer"]
		td.Cmp(t, present, false, "the request replaces the configuration except for secrets")
	})
}
