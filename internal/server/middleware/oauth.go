package middleware

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cristalhq/jwt/v5"
	"github.com/marsolab/servekit/errkit"
	"github.com/marsolab/servekit/httpkit"
)

// OAuthProvider interface for OAuth provider validation
type OAuthProvider interface {
	ValidateToken(ctx context.Context, tokenString string) (*OAuthClaims, error)
	GetPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error)
	GetIssuer() string
	GetAudience() string
}

// UserSyncer interface for user synchronization
type UserSyncer interface {
	SyncUser(ctx context.Context, oauthUser OAuthUser, providerName string) (*SyncedUser, error)
}

// OAuthClaims represents claims from an OAuth JWT token.
type OAuthClaims struct {
	Subject      string         `json:"sub"`
	Email        string         `json:"email"`
	Name         string         `json:"name,omitempty"`
	Picture      string         `json:"picture,omitempty"`
	Issuer       string         `json:"iss"`
	Audience     []string       `json:"aud"`
	ExpiresAt    int64          `json:"exp"`
	IssuedAt     int64          `json:"iat"`
	Organization string         `json:"org_code,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Teams        []string       `json:"teams,omitempty"`
	Permissions  []string       `json:"permissions,omitempty"`
	CustomClaims map[string]any `json:"-"`
}

// OAuthUser represents a user from OAuth claims
type OAuthUser struct {
	Subject      string         `json:"sub"`
	Email        string         `json:"email"`
	Name         string         `json:"name,omitempty"`
	Picture      string         `json:"picture,omitempty"`
	Roles        []string       `json:"roles,omitempty"`
	Organization string         `json:"organization,omitempty"`
	Teams        []string       `json:"teams,omitempty"`
	Claims       map[string]any `json:"claims,omitempty"`
}

// SyncedUser represents a synchronized user
type SyncedUser struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	Name        string    `json:"name,omitempty"`
	OrgID       string    `json:"org_id"`
	Provider    string    `json:"oauth_provider"`
	Subject     string    `json:"oauth_sub"`
	IsOAuthUser bool      `json:"is_oauth_user"`
	LastSyncAt  time.Time `json:"last_sync_at"`
}

// AuthenticateOAuth middleware validates OAuth JWT tokens and synchronizes users
func AuthenticateOAuth(
	provider OAuthProvider,
	syncer UserSyncer,
	providerName string,
	roleClaimName, orgClaimName, teamClaimName string,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				httpkit.ErrorHTTP(w, r, errkit.ErrUnauthenticated)
				return
			}

			// Remove "Bearer " prefix
			tokenString := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid authorization header format", errkit.ErrUnauthenticated))
				return
			}

			// Validate the OAuth token
			claims, err := provider.ValidateToken(r.Context(), tokenString)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("%w: invalid oauth token: %s", errkit.ErrUnauthenticated, err.Error()))
				return
			}

			// Extract user information from claims
			oauthUser := extractOAuthUser(claims, roleClaimName, orgClaimName, teamClaimName)

			// Sync user with local database
			syncedUser, err := syncer.SyncUser(r.Context(), oauthUser, providerName)
			if err != nil {
				httpkit.ErrorHTTP(w, r, fmt.Errorf("sync oauth user: %w", err))
				return
			}

			// Create user info for context
			userInfo := UserInfo{
				UserID: syncedUser.UserID,
				Email:  syncedUser.Email,
				Roles:  oauthUser.Roles,
			}

			// Store user info in context
			ctx := context.WithValue(r.Context(), UserContextKey, userInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractOAuthUser extracts user information from OAuth claims.
//
//nolint:cyclop // Multiple role and team claim configurations.
func extractOAuthUser(claims *OAuthClaims, roleClaimName, orgClaimName, teamClaimName string) OAuthUser {
	user := OAuthUser{
		Subject: claims.Subject,
		Email:   claims.Email,
		Name:    claims.Name,
		Picture: claims.Picture,
		Claims:  claims.CustomClaims,
	}

	// Extract roles from custom claim name or default
	if roleClaimName != "" {
		if roles, ok := claims.CustomClaims[roleClaimName]; ok {
			user.Roles = extractStringSlice(roles)
		}
	} else if len(claims.Roles) > 0 {
		user.Roles = claims.Roles
	}

	// Extract organization from custom claim name or default
	if orgClaimName != "" {
		if org, ok := claims.CustomClaims[orgClaimName]; ok {
			if orgStr, ok := org.(string); ok {
				user.Organization = orgStr
			}
		}
	} else if claims.Organization != "" {
		user.Organization = claims.Organization
	}

	// Extract teams from custom claim name or default
	if teamClaimName != "" {
		if teams, ok := claims.CustomClaims[teamClaimName]; ok {
			user.Teams = extractStringSlice(teams)
		}
	} else if len(claims.Teams) > 0 {
		user.Teams = claims.Teams
	}

	return user
}

// extractStringSlice safely extracts a string slice from an interface{}
func extractStringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		var result []string

		for _, item := range v {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	case string:
		return []string{v}
	default:
		return nil
	}
}

// GenericOAuthProvider provides a generic OAuth provider implementation
type GenericOAuthProvider struct {
	issuer   string
	audience string
	jwksURL  string
	keyCache map[string]*rsa.PublicKey
}

// NewGenericOAuthProvider creates a new generic OAuth provider
func NewGenericOAuthProvider(issuer, audience, jwksURL string) *GenericOAuthProvider {
	return &GenericOAuthProvider{
		issuer:   issuer,
		audience: audience,
		jwksURL:  jwksURL,
		keyCache: make(map[string]*rsa.PublicKey),
	}
}

// ValidateToken validates a JWT token.
//
//nolint:gocyclo,cyclop // Complex token validation and claim extraction.
func (p *GenericOAuthProvider) ValidateToken(ctx context.Context, tokenString string) (*OAuthClaims, error) {
	raw := []byte(tokenString)

	// Parse without verification first so we can read the kid from the header
	// and look up the right public key.
	headerToken, err := jwt.ParseNoVerify(raw)
	if err != nil {
		return nil, fmt.Errorf("parse token header: %w", err)
	}

	publicKey, err := p.GetPublicKey(ctx, headerToken.Header().KeyID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	verifier, err := jwt.NewVerifierRS(jwt.RS256, publicKey)
	if err != nil {
		return nil, fmt.Errorf("create verifier: %w", err)
	}

	token, err := jwt.Parse(raw, verifier)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// Extract claims
	var stdClaims jwt.RegisteredClaims
	if err := token.DecodeClaims(&stdClaims); err != nil {
		return nil, fmt.Errorf("decode standard claims: %w", err)
	}

	// Extract custom claims
	var customClaims map[string]any
	if err := token.DecodeClaims(&customClaims); err != nil {
		return nil, fmt.Errorf("decode custom claims: %w", err)
	}

	// Validate issuer and audience
	if stdClaims.Issuer != p.issuer {
		return nil, fmt.Errorf("invalid issuer: %s", stdClaims.Issuer)
	}

	validAudience := false

	for _, aud := range stdClaims.Audience {
		if aud == p.audience {
			validAudience = true

			break
		}
	}

	if !validAudience {
		return nil, errors.New("invalid audience")
	}

	// Check expiration.
	if stdClaims.ExpiresAt != nil && stdClaims.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("token expired")
	}

	// Build OAuth claims
	claims := &OAuthClaims{
		Subject:      stdClaims.Subject,
		Issuer:       stdClaims.Issuer,
		Audience:     stdClaims.Audience,
		CustomClaims: customClaims,
	}

	// Extract standard fields from custom claims
	if email, ok := customClaims["email"].(string); ok {
		claims.Email = email
	}

	if name, ok := customClaims["name"].(string); ok {
		claims.Name = name
	}

	if picture, ok := customClaims["picture"].(string); ok {
		claims.Picture = picture
	}

	if org, ok := customClaims["org_code"].(string); ok {
		claims.Organization = org
	}

	if stdClaims.ExpiresAt != nil {
		claims.ExpiresAt = stdClaims.ExpiresAt.Unix()
	}

	if stdClaims.IssuedAt != nil {
		claims.IssuedAt = stdClaims.IssuedAt.Unix()
	}

	return claims, nil
}

// GetPublicKey retrieves a public key for token verification
func (p *GenericOAuthProvider) GetPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	// This is a simplified implementation
	// In practice, you would fetch from JWKS endpoint and cache the keys
	return nil, errors.New("JWKS key fetching not implemented - use a proper JWKS library")
}

// GetIssuer returns the OAuth provider issuer
func (p *GenericOAuthProvider) GetIssuer() string {
	return p.issuer
}

// GetAudience returns the OAuth provider audience
func (p *GenericOAuthProvider) GetAudience() string {
	return p.audience
}
