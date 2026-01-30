package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cristalhq/jwt/v5"
)

const (
	// Token durations
	AccessTokenDuration  = 15 * time.Minute   // Short-lived access tokens
	RefreshTokenDuration = 7 * 24 * time.Hour // Long-lived refresh tokens
)

// Claims represents the JWT claims with role information
type Claims struct {
	jwt.RegisteredClaims
	UserID string   `json:"user_id"`
	Email  string   `json:"email"`
	Roles  []string `json:"roles"` // Array of role names
}

// JWTService handles JWT token generation and validation
type JWTService struct {
	signer   jwt.Signer
	verifier jwt.Verifier
	issuer   string
}

// NewJWTService creates a new JWT service
func NewJWTService(secretKey string, issuer string) *JWTService {
	key := []byte(secretKey)
	signer, err := jwt.NewSignerHS(jwt.HS256, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create JWT signer: %v", err))
	}

	verifier, err := jwt.NewVerifierHS(jwt.HS256, key)
	if err != nil {
		panic(fmt.Sprintf("failed to create JWT verifier: %v", err))
	}

	return &JWTService{
		signer:   signer,
		verifier: verifier,
		issuer:   issuer,
	}
}

// GenerateAccessToken generates a new access token with role claims
func (s *JWTService) GenerateAccessToken(userID, email string, roles []string) (string, error) {
	now := time.Now()
	expiresAt := now.Add(AccessTokenDuration)

	// Generate a unique JWT ID for token revocation
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Subject:   userID,
			Issuer:    s.issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(now),
		},
		UserID: userID,
		Email:  email,
		Roles:  roles,
	}

	// Build and sign the token
	builder := jwt.NewBuilder(s.signer)
	token, err := builder.Build(claims)
	if err != nil {
		return "", fmt.Errorf("failed to build token: %w", err)
	}

	return token.String(), nil
}

// GenerateRefreshToken generates a new refresh token (opaque token, not JWT)
// Returns the raw token and its hash for storage
func (s *JWTService) GenerateRefreshToken() (token string, tokenHash string, err error) {
	// Generate a 32-byte random token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	token = hex.EncodeToString(tokenBytes)

	// For simplicity, we'll use the token itself as the hash
	// In a production system, you'd want to hash this
	tokenHash = token

	return token, tokenHash, nil
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*Claims, error) {
	// Parse the token
	token, err := jwt.Parse([]byte(tokenString), s.verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Decode claims
	var claims Claims
	err = token.DecodeClaims(&claims)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	// Validate standard claims
	now := time.Now()

	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(now) {
		return nil, fmt.Errorf("token has expired")
	}

	// Check not before
	if claims.NotBefore != nil && claims.NotBefore.Time.After(now) {
		return nil, fmt.Errorf("token not yet valid")
	}

	// Check issuer
	if claims.Issuer != s.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return &claims, nil
}

// ExtractTokenID extracts the JTI from a token without full validation
// This is useful for adding tokens to the deny list
func (s *JWTService) ExtractTokenID(tokenString string) (string, error) {
	// Parse without signature verification for extracting JTI
	token, err := jwt.ParseNoVerify([]byte(tokenString))
	if err != nil {
		return "", fmt.Errorf("failed to parse token: %w", err)
	}

	var claims Claims
	err = token.DecodeClaims(&claims)
	if err != nil {
		return "", fmt.Errorf("failed to decode claims: %w", err)
	}

	return claims.ID, nil
}

// generateJTI generates a unique JWT ID
func generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
