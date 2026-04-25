# OAuth Integration with Organizations and Teams

This document describes the OAuth integration system and multi-tenant organization/team support in PlainQ.

## Overview

PlainQ supports integation with external OAuth providers (like Kinde, Auth0, Okta, Google, etc.) while maintaining its internal RBAC system. The system provides:

- **OAuth Provider Integration**: Support for multiple OAuth providers
- **User Synchronization**: Automatic user sync from OAuth to local database
- **Organization Multi-tenancy**: Support for multiple organizations
- **Team-based Permissions**: Fine-grained access control via teams
- **Hybrid Authentication**: Both local and OAuth authentication

## Architecture

### Components

1. **OAuth Service** (`internal/server/service/oauth/`)
   - OAuth provider management
   - User synchronization
   - Organization and team management

2. **OAuth Middleware** (`internal/server/middleware/oauth.go`)
   - JWT token validation from external providers
   - Automatic user synchronization
   - Context injection for authenticated users

3. **Enhanced Database Schema**
   - Organizations and teams support
   - OAuth user tracking
   - Team-based permissions

## Configuration

### OAuth Settings

```go
type Config struct {
    // OAuth configuration
    OAuthEnable             bool          // Enable OAuth integration
    OAuthProvider           string        // "kinde", "auth0", "okta", "google", etc.
    OAuthClientID           string        // OAuth client ID
    OAuthClientSecret       string        // OAuth client secret
    OAuthDomain             string        // OAuth provider domain
    OAuthAudience           string        // OAuth audience
    OAuthCallbackURL        string        // OAuth callback URL
    OAuthScope              string        // OAuth scope
    OAuthJWKSURL            string        // JWKS endpoint URL
    OAuthUserSyncEnable     bool          // Enable user synchronization
    OAuthUserSyncInterval   time.Duration // Sync interval
    OAuthRoleClaimName      string        // JWT claim name for roles
    OAuthOrgClaimName       string        // JWT claim name for organization
    OAuthTeamClaimName      string        // JWT claim name for teams

    // Organization and team features
    MultiTenancyEnable      bool          // Enable multi-tenancy
    DefaultOrganization     string        // Default org for single-tenant mode
    TeamBasedPermissions    bool          // Enable team-based permissions
}
```

### Environment Variables

```bash
# OAuth Configuration
OAUTH_ENABLE=true
OAUTH_PROVIDER=kinde
OAUTH_CLIENT_ID=your_client_id
OAUTH_CLIENT_SECRET=your_client_secret
OAUTH_DOMAIN=yourdomain.kinde.com
OAUTH_AUDIENCE=your_audience
OAUTH_CALLBACK_URL=http://localhost:8080/oauth/callback
OAUTH_SCOPE="openid profile email"
OAUTH_JWKS_URL=https://yourdomain.kinde.com/.well-known/jwks
OAUTH_ROLE_CLAIM_NAME=roles
OAUTH_ORG_CLAIM_NAME=org_code
OAUTH_TEAM_CLAIM_NAME=teams

# Multi-tenancy
MULTI_TENANCY_ENABLE=true
DEFAULT_ORGANIZATION=default
TEAM_BASED_PERMISSIONS=true
```

## Database Schema

### Organizations

```sql
CREATE TABLE organizations (
    org_id      VARCHAR(26) PRIMARY KEY,
    org_code    TEXT UNIQUE NOT NULL,     -- Short code: "acme", "example-corp"
    org_name    TEXT NOT NULL,            -- Display name: "Acme Corporation"
    org_domain  TEXT,                     -- Domain for email-based assignment
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Teams

```sql
CREATE TABLE teams (
    team_id     VARCHAR(26) PRIMARY KEY,
    org_id      VARCHAR(26) NOT NULL,
    team_name   TEXT NOT NULL,
    team_code   TEXT NOT NULL,            -- Short code: "dev", "ops", "marketing"
    description TEXT,
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES organizations (org_id)
);
```

### Enhanced Users Table

```sql
ALTER TABLE users ADD COLUMN org_id VARCHAR(26);
ALTER TABLE users ADD COLUMN oauth_provider TEXT;
ALTER TABLE users ADD COLUMN oauth_sub TEXT;      -- OAuth subject identifier
ALTER TABLE users ADD COLUMN last_sync_at TIMESTAMP;
ALTER TABLE users ADD COLUMN is_oauth_user BOOLEAN DEFAULT FALSE;
```

### User Teams Mapping

```sql
CREATE TABLE user_teams (
    user_id    VARCHAR(26),
    team_id    VARCHAR(26),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, team_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id),
    FOREIGN KEY (team_id) REFERENCES teams (team_id)
);
```

### Team Roles

```sql
CREATE TABLE team_roles (
    team_id    VARCHAR(26),
    role_id    VARCHAR(26),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id, role_id),
    FOREIGN KEY (team_id) REFERENCES teams (team_id),
    FOREIGN KEY (role_id) REFERENCES roles (role_id)
);
```

### Organization-scoped Queue Permissions

```sql
CREATE TABLE org_queue_permissions (
    org_id      VARCHAR(26),
    queue_id    VARCHAR(26),
    role_id     VARCHAR(26),
    can_send    BOOLEAN DEFAULT FALSE,
    can_receive BOOLEAN DEFAULT FALSE,
    can_purge   BOOLEAN DEFAULT FALSE,
    can_delete  BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (org_id, queue_id, role_id)
);
```

## OAuth Provider Integration

### Supported Providers

#### Kinde

```go
// Kinde configuration
config := &Config{
    OAuthProvider:        "kinde",
    OAuthDomain:          "yourdomain.kinde.com",
    OAuthClientID:        "your_client_id",
    OAuthClientSecret:    "your_client_secret",
    OAuthAudience:        "your_audience",
    OAuthJWKSURL:         "https://yourdomain.kinde.com/.well-known/jwks",
    OAuthRoleClaimName:   "roles",
    OAuthOrgClaimName:    "org_code",
    OAuthTeamClaimName:   "teams",
}
```

#### Auth0

```go
// Auth0 configuration
config := &Config{
    OAuthProvider:        "auth0",
    OAuthDomain:          "yourdomain.auth0.com",
    OAuthClientID:        "your_client_id",
    OAuthClientSecret:    "your_client_secret",
    OAuthAudience:        "your_audience",
    OAuthJWKSURL:         "https://yourdomain.auth0.com/.well-known/jwks.json",
    OAuthRoleClaimName:   "https://yourdomain.com/roles",
    OAuthOrgClaimName:    "https://yourdomain.com/org_code",
    OAuthTeamClaimName:   "https://yourdomain.com/teams",
}
```

### JWT Token Structure

Expected JWT token claims:

```json
{
  "sub": "oauth_user_id",
  "email": "user@example.com",
  "name": "John Doe",
  "picture": "https://example.com/avatar.jpg",
  "iss": "https://yourdomain.kinde.com",
  "aud": ["your_audience"],
  "exp": 1704067200,
  "iat": 1704063600,
  "roles": ["admin", "developer"],
  "org_code": "acme",
  "teams": ["dev", "ops"],
  "permissions": ["read:queues", "write:queues"]
}
```

## User Synchronization

### Automatic Sync Flow

1. **OAuth Token Validation**: Validate incoming JWT token
2. **Extract User Data**: Extract user info from token claims
3. **Organization Resolution**: Determine user's organization
4. **User Sync**: Create or update user in local database
5. **Role Assignment**: Assign roles based on OAuth claims
6. **Team Membership**: Sync team memberships

### Sync Strategies

#### Real-time Sync (Recommended)

```go
// Middleware automatically syncs on each request
router.Use(middleware.AuthenticateOAuth(
    oauthProvider, 
    oauthService, 
    "kinde",
    "roles",      // role claim name
    "org_code",   // organization claim name
    "teams",      // teams claim name
))
```

#### Periodic Sync

```go
// Background sync every hour
go func() {
    ticker := time.NewTicker(time.Hour)
    for range ticker.C {
        syncAllUsers()
    }
}()
```

### Organization Assignment Logic

1. **OAuth Claim**: Use `org_code` from JWT token
2. **Email Domain**: Match email domain to organization
3. **Default Org**: Fall back to default organization

```go
func determineOrganization(user OAuthUser) string {
    // Priority 1: OAuth claim
    if user.Organization != "" {
        return user.Organization
    }
    
    // Priority 2: Email domain
    domain := extractDomain(user.Email)
    if org := getOrgByDomain(domain); org != nil {
        return org.Code
    }
    
    // Priority 3: Default
    return "default"
}
```

## API Endpoints

### OAuth Provider Management

```bash
# List OAuth providers
GET /oauth/providers

# Create OAuth provider
POST /oauth/providers
{
  "provider_name": "kinde",
  "org_id": "01HQ...",
  "config": {
    "domain": "yourdomain.kinde.com",
    "client_id": "your_client_id",
    "audience": "your_audience"
  }
}

# Update OAuth provider
PUT /oauth/providers/{providerID}

# Delete OAuth provider
DELETE /oauth/providers/{providerID}
```

### User Synchronization

```bash
# Manually sync user
POST /oauth/sync/user
{
  "provider": "kinde",
  "user": {
    "sub": "oauth_user_id",
    "email": "user@example.com",
    "name": "John Doe",
    "roles": ["developer"],
    "organization": "acme",
    "teams": ["dev", "frontend"]
  }
}

# Get user sync status
GET /oauth/sync/user/{userID}
```

### Organization Management

```bash
# List organizations
GET /oauth/organizations

# List teams in organization
GET /oauth/organizations/{orgID}/teams
```

### Team Management

```bash
# Get user's teams
GET /oauth/users/{userID}/teams

# Assign user to team
POST /oauth/users/{userID}/teams/{teamID}

# Remove user from team
DELETE /oauth/users/{userID}/teams/{teamID}
```

## Middleware Usage

### OAuth Authentication

```go
// OAuth middleware for external tokens
oauthProvider := middleware.NewGenericOAuthProvider(
    cfg.OAuthDomain,
    cfg.OAuthAudience,
    cfg.OAuthJWKSURL,
)

router.Use(middleware.AuthenticateOAuth(
    oauthProvider,
    oauthService,
    cfg.OAuthProvider,
    cfg.OAuthRoleClaimName,
    cfg.OAuthOrgClaimName,
    cfg.OAuthTeamClaimName,
))
```

### Hybrid Authentication

```go
// Support both local and OAuth tokens
router.Route("/api", func(r chi.Router) {
    // Try OAuth first, fall back to local JWT
    r.Use(middleware.AuthenticateHybrid(
        localTokenManager,
        oauthProvider,
        oauthService,
        cfg,
    ))
    
    // Protected routes
    r.Get("/profile", profileHandler)
})
```

### Organization Isolation

```go
// Ensure users can only access their organization's resources
router.Use(middleware.RequireOrganization())

// Organization-specific queue access
router.Route("/orgs/{orgID}/queues", func(r chi.Router) {
    r.Use(middleware.ValidateOrgAccess())
    r.Get("/", listOrgQueuesHandler)
})
```

## Permission Model

### Hierarchy

1. **System Roles**: Global roles (admin, user)
2. **Organization Roles**: Org-specific roles
3. **Team Roles**: Team-based roles
4. **Queue Permissions**: Granular queue access

### Permission Resolution

```go
func hasQueuePermission(userID, queueID, permission string) bool {
    // 1. Check system admin
    if isSystemAdmin(userID) {
        return true
    }
    
    // 2. Check organization admin
    if isOrgAdmin(userID, getQueueOrg(queueID)) {
        return true
    }
    
    // 3. Check team permissions
    if hasTeamPermission(userID, queueID, permission) {
        return true
    }
    
    // 4. Check individual user permissions
    return hasUserPermission(userID, queueID, permission)
}
```

## Security Considerations

### Token Validation

- **JWKS Validation**: Verify tokens using provider's public keys
- **Issuer Validation**: Ensure token is from expected provider
- **Audience Validation**: Verify token is intended for PlainQ
- **Expiration Checking**: Reject expired tokens

### User Synchronization

- **Race Condition Protection**: Use database transactions
- **Data Validation**: Validate all OAuth claims
- **Organization Isolation**: Prevent cross-org data access
- **Audit Logging**: Log all sync operations

### Multi-tenancy

- **Data Isolation**: Ensure org-specific data access
- **Queue Scoping**: Limit queue access by organization
- **Team Validation**: Verify team membership before access

## Example Integration

### Complete Server Setup

```go
func setupOAuthIntegration(cfg *config.Config, db *sql.DB) {
    // Initialize services
    oauthStorage := oauth.NewSQLiteStorage(db)
    oauthService := oauth.NewService(cfg, logger, oauthStorage)
    
    // Setup OAuth provider
    oauthProvider := middleware.NewGenericOAuthProvider(
        cfg.OAuthDomain,
        cfg.OAuthAudience,
        cfg.OAuthJWKSURL,
    )
    
    // Setup router with OAuth middleware
    r := chi.NewRouter()
    
    if cfg.OAuthEnable {
        // OAuth authentication
        r.Use(middleware.AuthenticateOAuth(
            oauthProvider,
            oauthService,
            cfg.OAuthProvider,
            cfg.OAuthRoleClaimName,
            cfg.OAuthOrgClaimName,
            cfg.OAuthTeamClaimName,
        ))
    } else {
        // Local JWT authentication
        r.Use(middleware.AuthenticateJWT(tokenManager))
    }
    
    // Organization-aware routes
    if cfg.MultiTenancyEnable {
        r.Route("/orgs/{orgID}", func(r chi.Router) {
            r.Use(middleware.ValidateOrgAccess())
            r.Mount("/queues", queueService)
        })
    }
    
    // Admin routes
    r.Route("/admin", func(r chi.Router) {
        r.Use(middleware.RequireAdmin())
        r.Mount("/oauth", oauthService)
    })
}
```

### Frontend Integration

```javascript
// OAuth login flow
const loginWithOAuth = async () => {
  // Redirect to OAuth provider
  window.location.href = `https://yourdomain.kinde.com/oauth2/authorize?${new URLSearchParams({
    client_id: 'your_client_id',
    response_type: 'code',
    scope: 'openid profile email',
    redirect_uri: 'http://localhost:3000/callback',
    state: generateState(),
  })}`;
};

// Handle OAuth callback
const handleCallback = async (code) => {
  const response = await fetch('/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  
  const { access_token } = await response.json();
  
  // Use token for PlainQ API calls
  localStorage.setItem('token', access_token);
};

// API calls with OAuth token
const apiCall = async (endpoint) => {
  const token = localStorage.getItem('token');
  return fetch(`/api${endpoint}`, {
    headers: {
      'Authorization': `Bearer ${token}`,
    },
  });
};
```

## Migration from Local to OAuth

### Step-by-Step Migration

1. **Enable OAuth**: Configure OAuth settings
2. **User Mapping**: Map existing users to OAuth subjects
3. **Gradual Rollout**: Support both auth methods during transition
4. **Data Migration**: Migrate user data to new schema
5. **Full Cutover**: Disable local authentication

### Migration Script Example

```go
func migrateToOAuth(db *sql.DB) error {
    // 1. Add OAuth columns to existing users
    if err := addOAuthColumns(db); err != nil {
        return err
    }
    
    // 2. Create default organization
    if err := createDefaultOrg(db); err != nil {
        return err
    }
    
    // 3. Assign users to default organization
    if err := assignUsersToDefaultOrg(db); err != nil {
        return err
    }
    
    // 4. Create default teams
    if err := createDefaultTeams(db); err != nil {
        return err
    }
    
    return nil
}
```

This completes the OAuth integration with organizations and teams support for PlainQ!
