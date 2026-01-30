package auth

import (
	"context"
	"time"
)

// User represents a user account
type User struct {
	UserID    string
	Email     string
	Password  string
	Verified  bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Role represents a role
type Role struct {
	RoleID    string
	RoleName  string
	CreatedAt time.Time
}

// RefreshToken represents a refresh token
type RefreshToken struct {
	TokenID    string
	UserID     string
	TokenHash  string
	ExpiresAt  time.Time
	Revoked    bool
	RevokedAt  *time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time
	DeviceInfo string
	IPAddress  string
}

// OAuthProvider represents an OAuth/OIDC provider configuration
type OAuthProvider struct {
	ProviderID      string
	ProviderName    string
	ProviderType    string
	Enabled         bool
	ClientID        string
	ClientSecret    string
	IssuerURL       string
	AuthURL         string
	TokenURL        string
	UserinfoURL     string
	JWKSURL         string
	Scopes          string
	SAMLMetadataURL string
	SAMLEntityID    string
	ConfigJSON      string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// OAuthConnection represents a user's connection to an OAuth provider
type OAuthConnection struct {
	ConnectionID   string
	UserID         string
	ProviderID     string
	ProviderUserID string
	Email          string
	ProfileData    string
	AccessToken    string
	RefreshToken   string
	ExpiresAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// QueuePermission represents permissions for a role on a specific queue
type QueuePermission struct {
	QueueID    string
	RoleID     string
	CanSend    bool
	CanReceive bool
	CanPurge   bool
	CanDelete  bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// PermissionAction represents an action that can be performed on a queue
type PermissionAction string

const (
	ActionSend    PermissionAction = "send"
	ActionReceive PermissionAction = "receive"
	ActionPurge   PermissionAction = "purge"
	ActionDelete  PermissionAction = "delete"
)

// AuthStorage defines the interface for authentication-related storage operations
type AuthStorage interface {
	// User operations
	CreateUser(ctx context.Context, email, passwordHash string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByID(ctx context.Context, userID string) (*User, error)
	UpdateUserPassword(ctx context.Context, userID, passwordHash string) error
	UpdateUserVerified(ctx context.Context, userID string, verified bool) error
	GetUserRoles(ctx context.Context, userID string) ([]Role, error)
	AssignRole(ctx context.Context, userID, roleID string) error

	// System state operations
	IsSetupCompleted(ctx context.Context) (bool, error)
	MarkSetupCompleted(ctx context.Context) error

	// Refresh token operations
	CreateRefreshToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time, deviceInfo, ipAddress string) (*RefreshToken, error)
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserRefreshTokens(ctx context.Context, userID string) error
	UpdateRefreshTokenLastUsed(ctx context.Context, tokenID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) error

	// Token deny list operations
	AddToDenyList(ctx context.Context, jti, userID string, expiresAt time.Time, reason string) error
	IsTokenDenied(ctx context.Context, jti string) (bool, error)
	GetActiveDeniedTokens(ctx context.Context) (map[string]time.Time, error)
	CleanupExpiredDeniedTokens(ctx context.Context) error

	// OAuth provider operations
	CreateOAuthProvider(ctx context.Context, provider *OAuthProvider) error
	GetOAuthProvider(ctx context.Context, providerName string) (*OAuthProvider, error)
	GetOAuthProviderByID(ctx context.Context, providerID string) (*OAuthProvider, error)
	ListEnabledOAuthProviders(ctx context.Context) ([]OAuthProvider, error)
	UpdateOAuthProvider(ctx context.Context, provider *OAuthProvider) error

	// OAuth connection operations
	CreateOAuthConnection(ctx context.Context, conn *OAuthConnection) error
	GetOAuthConnection(ctx context.Context, providerID, providerUserID string) (*OAuthConnection, error)
	GetUserOAuthConnections(ctx context.Context, userID string) ([]OAuthConnection, error)
	UpdateOAuthConnection(ctx context.Context, conn *OAuthConnection) error
	DeleteOAuthConnection(ctx context.Context, connectionID string) error

	// Audit log
	LogAuthEvent(ctx context.Context, userID, eventType string, success bool, ipAddress, userAgent, metadata string) error

	// Queue permission operations
	GetQueuePermissions(ctx context.Context, queueID string, roleIDs []string) (*QueuePermission, error)
	SetQueuePermissions(ctx context.Context, perm *QueuePermission) error
	DeleteQueuePermissions(ctx context.Context, queueID, roleID string) error
	GetRoleByName(ctx context.Context, roleName string) (*Role, error)
}
