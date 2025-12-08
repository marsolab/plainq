# PlainQ Authentication & Authorization System

This document describes the authentication and authorization system implemented in PlainQ.

## Overview

PlainQ now includes a comprehensive authentication and authorization system with the following features:

- **JWT-based authentication** with role claims
- **Role-Based Access Control (RBAC)** for fine-grained permissions
- **Token invalidation** using a deny list (TTL+1 approach)
- **Refresh token** support with revocation
- **First-time setup flow** for creating an admin account
- **OAuth/OIDC provider integration** architecture for external identity providers
- **Audit logging** for all authentication events

## Architecture

### Core Components

1. **JWT Service** (`internal/server/auth/jwt.go`)
   - Generates and validates JWT access tokens
   - Embeds user roles in JWT claims
   - Access tokens are short-lived (15 minutes)
   - Uses HS256 signing algorithm

2. **Password Hashing** (`internal/server/auth/password.go`)
   - Uses Argon2id for secure password hashing
   - OWASP recommended parameters
   - Automatic migration from plaintext passwords

3. **Token Deny List** (`internal/server/auth/denylist.go`)
   - In-memory cache backed by database
   - TTL+1 approach for token invalidation
   - Automatic cleanup of expired tokens

4. **Authentication Service** (`internal/server/auth/service.go`)
   - Handles login, signup, refresh, and logout operations
   - Issues both access and refresh tokens
   - Manages token revocation

5. **OAuth Provider Integration** (`internal/server/auth/oauth.go`)
   - Pluggable architecture for OAuth/OIDC providers
   - Support for Kinde, Auth0, Okta, WorkOS, etc.
   - Automatic user creation and linking

6. **HTTP Middleware** (`internal/server/middleware/auth.go`)
   - Validates JWT tokens from Authorization header
   - Injects user claims into request context
   - Role-based authorization

7. **gRPC Interceptor** (`internal/server/interceptor/auth.go`)
   - Validates JWT tokens from gRPC metadata
   - Same functionality as HTTP middleware

## Database Schema

### Users & Roles

```sql
users (user_id, email, password, verified, created_at, updated_at)
roles (role_id, role_name, created_at)
user_roles (user_id, role_id, created_at)
```

**Default Roles:**
- `admin` - Full access to all resources
- `producer` - Can send messages to queues
- `consumer` - Can receive messages from queues

### Token Management

```sql
refresh_tokens (token_id, user_id, token_hash, expires_at, revoked, ...)
token_denylist (jti, user_id, expires_at, revoked_at, reason)
```

### OAuth Integration

```sql
oauth_providers (provider_id, provider_name, provider_type, enabled, ...)
oauth_connections (connection_id, user_id, provider_id, provider_user_id, ...)
```

### Audit & System State

```sql
auth_audit_log (log_id, user_id, event_type, success, ip_address, ...)
system_state (key, value, updated_at)
```

## API Endpoints

### Public Endpoints (No Authentication Required)

#### Setup

```http
GET /api/v1/auth/setup/status
```

Response:
```json
{
  "setup_completed": false
}
```

```http
POST /api/v1/auth/setup
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "SecurePassword123"
}
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "a1b2c3...",
  "user": {
    "user_id": "01HQ5RJNXS...",
    "email": "admin@example.com",
    "verified": true,
    "roles": ["admin"]
  }
}
```

#### Login

```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "a1b2c3...",
  "user": {
    "user_id": "01HQ5RJNXS...",
    "email": "user@example.com",
    "verified": true,
    "roles": ["consumer"]
  }
}
```

#### Signup

```http
POST /api/v1/auth/signup
Content-Type: application/json

{
  "email": "newuser@example.com",
  "password": "SecurePassword123"
}
```

Response: Same as login

#### Refresh Token

```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "a1b2c3..."
}
```

Response: Same as login (new access token)

#### Logout

```http
POST /api/v1/auth/logout
Authorization: Bearer eyJhbGc...
Content-Type: application/json

{
  "refresh_token": "a1b2c3..."
}
```

Response:
```json
{
  "message": "logged out successfully"
}
```

### Protected Endpoints (Authentication Required)

All queue-related endpoints now require authentication when auth is enabled:

```http
GET /api/v1/queue/
Authorization: Bearer eyJhbGc...
```

## Configuration

### Environment Variables / CLI Flags

```bash
# Enable/disable authentication (default: true)
--auth.enable=true

# JWT signing secret (required if auth enabled)
# Generate with: openssl rand -hex 32
--auth.jwt-secret="your-secret-key"

# JWT issuer (default: "plainq")
--auth.issuer="plainq"
```

### Example Server Start

```bash
# With explicit JWT secret
./plainq server --auth.jwt-secret="abc123..."

# Without JWT secret (will generate random secret)
# WARNING: Tokens will be invalidated on server restart
./plainq server
```

## First-Time Setup Flow

1. **Start the server** - Authentication is enabled by default
2. **Check setup status** - `GET /api/v1/auth/setup/status`
3. **Create admin account** - `POST /api/v1/auth/setup` (only available before setup is complete)
4. **Setup is marked complete** - Subsequent calls to `/setup` will return 409 Conflict
5. **Use admin credentials** to login and manage the system

## Token Lifecycle

### Access Token
- **Lifetime:** 15 minutes
- **Storage:** Client-side (memory or localStorage)
- **Contains:** User ID, email, roles, expiration
- **Invalidation:** Added to deny list on logout or password change

### Refresh Token
- **Lifetime:** 7 days
- **Storage:** Client-side (httpOnly cookie recommended for web apps)
- **Format:** Opaque random token (not JWT)
- **Invalidation:** Revoked in database on logout or security events

## OAuth Provider Integration

### Architecture

The OAuth system is designed to support multiple providers through a unified interface:

```
┌─────────────────┐
│  OAuth Service  │
└────────┬────────┘
         │
    ┌────┴─────┬──────────┬──────────┐
    │          │          │          │
┌───▼────┐ ┌──▼────┐ ┌──▼────┐ ┌──▼────┐
│ Kinde  │ │ Auth0 │ │ Okta  │ │WorkOS │
└────────┘ └───────┘ └───────┘ └───────┘
```

### Adding a Provider

1. **Create provider entry** in `oauth_providers` table:
```sql
INSERT INTO oauth_providers (
  provider_id, provider_name, provider_type, enabled,
  client_id, client_secret, issuer_url, scopes
) VALUES (
  '01HQ...', 'kinde', 'oidc', true,
  'your-client-id', 'your-client-secret',
  'https://your-tenant.kinde.com',
  '["openid", "email", "profile"]'
);
```

2. **Implement OAuth callback endpoint** (if not using generic OIDC flow)

3. **Users can now login** via OAuth provider

### Supported Provider Types

- `oidc` - OpenID Connect (generic)
- `oauth2` - OAuth 2.0
- `saml` - SAML (configuration via metadata URL)

### Example Providers

**Kinde:**
```json
{
  "provider_type": "oidc",
  "issuer_url": "https://your-tenant.kinde.com",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["openid", "email", "profile"]
}
```

**Auth0:**
```json
{
  "provider_type": "oidc",
  "issuer_url": "https://your-tenant.auth0.com",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["openid", "email", "profile"]
}
```

**Okta:**
```json
{
  "provider_type": "oidc",
  "issuer_url": "https://your-domain.okta.com",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["openid", "email", "profile"]
}
```

**WorkOS:**
```json
{
  "provider_type": "oidc",
  "issuer_url": "https://api.workos.com",
  "client_id": "...",
  "client_secret": "...",
  "scopes": ["openid", "email", "profile"]
}
```

## RBAC (Role-Based Access Control)

### Queue Permissions

Permissions can be assigned per-queue, per-role:

```sql
INSERT INTO queue_permissions (
  queue_id, role_id, can_send, can_receive, can_purge, can_delete
) VALUES (
  '01HQ...', '01HQ...', true, false, false, false
);
```

**Permissions:**
- `can_send` - Can send messages to the queue
- `can_receive` - Can receive messages from the queue
- `can_purge` - Can purge all messages
- `can_delete` - Can delete the queue

### Using Roles in Code

HTTP Middleware:
```go
router.With(middleware.RequireRole("admin")).Post("/admin/endpoint", handler)
```

gRPC:
```go
claims, ok := interceptor.GetClaimsFromContext(ctx)
if ok {
    // Check claims.Roles
}
```

## Security Features

### Token Invalidation (Deny List)

When a user logs out or changes their password, their access token is added to the deny list:

1. Token JTI (JWT ID) is extracted
2. Entry is created in `token_denylist` with original expiration
3. In-memory cache is updated for fast lookups
4. Expired entries are cleaned up automatically (TTL+1)

### Refresh Token Revocation

Refresh tokens can be revoked:
- On logout
- On password change
- On security events (admin action)
- All tokens for a user can be revoked at once

### Audit Logging

All authentication events are logged:
```sql
SELECT * FROM auth_audit_log
WHERE user_id = '01HQ...'
ORDER BY created_at DESC;
```

Events tracked:
- `login` - User login attempts
- `logout` - User logout
- `signup` - New user registration
- `token_refresh` - Token refresh attempts
- `password_change` - Password changes
- `setup` - Initial admin setup

## Migration from Existing Systems

### Plaintext Password Migration

The system automatically migrates plaintext passwords to Argon2 hashes:

1. On first login, plaintext password is checked
2. If valid, password is hashed and updated
3. Future logins use the hash

### Disabling Authentication

To disable authentication (not recommended for production):

```bash
./plainq server --auth.enable=false
```

## Best Practices

1. **Always set a strong JWT secret** in production
2. **Use HTTPS** to protect tokens in transit
3. **Store JWT secret securely** (environment variable, secrets manager)
4. **Rotate JWT secret periodically** and handle token invalidation
5. **Use httpOnly cookies** for refresh tokens in web apps
6. **Implement rate limiting** on auth endpoints
7. **Monitor audit logs** for suspicious activity
8. **Enable MFA** when using OAuth providers that support it

## Troubleshooting

### "invalid or expired token"

- Check token expiration (access tokens expire in 15 minutes)
- Verify JWT secret matches between server restarts
- Check if token was explicitly revoked (logout, password change)

### "setup already completed"

- Setup can only be run once
- To reset: delete database or update `system_state` table

### "missing authorization header"

- Ensure `Authorization: Bearer <token>` header is present
- Check that auth is enabled on the server

## Future Enhancements

Potential improvements:

- [ ] Session management (track all active sessions)
- [ ] Password reset via email
- [ ] Email verification flow
- [ ] Two-factor authentication (TOTP)
- [ ] API keys for service-to-service auth
- [ ] More granular permissions (ACLs)
- [ ] IP whitelisting
- [ ] Rate limiting per user/IP
- [ ] WebAuthn/Passkey support
