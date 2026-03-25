# Authentication and RBAC Implementation

This document describes the authentication and Role-Based Access Control (RBAC) system implemented in PlainQ.

## Overview

The PlainQ authentication and RBAC system provides:
- JWT-based authentication
- Role-based authorization
- Queue-level permissions
- Middleware for protecting endpoints
- Administrative role management

## Architecture

### Components

1. **Authentication Service** (`internal/server/service/account/`)
   - User registration and login
   - JWT token generation and validation
   - Password management
   - User account management

2. **RBAC Service** (`internal/server/service/rbac/`)
   - Role management
   - User-role assignments
   - Queue permission management
   - Permission checking

3. **Middleware** (`internal/server/middleware/`)
   - JWT authentication middleware
   - Role-based authorization middleware
   - Queue permission middleware

4. **Storage** 
   - SQLite-based storage implementations
   - Database schema for users, roles, and permissions

## Database Schema

### Core Tables

#### Users Table
```sql
CREATE TABLE users (
    user_id          VARCHAR(26) PRIMARY KEY,
    email            TEXT UNIQUE NOT NULL,
    password         TEXT NOT NULL,
    verified         BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Roles Table
```sql
CREATE TABLE roles (
    role_id    VARCHAR(26) PRIMARY KEY,
    role_name  TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### User Roles Table
```sql
CREATE TABLE user_roles (
    user_id    VARCHAR(26),
    role_id    VARCHAR(26),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE
);
```

#### Queue Permissions Table
```sql
CREATE TABLE queue_permissions (
    queue_id   VARCHAR(26),
    role_id    VARCHAR(26),
    can_send   BOOLEAN DEFAULT FALSE,
    can_receive BOOLEAN DEFAULT FALSE,
    can_purge  BOOLEAN DEFAULT FALSE,
    can_delete BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (queue_id, role_id),
    FOREIGN KEY (queue_id) REFERENCES queue_properties (queue_id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles (role_id) ON DELETE CASCADE
);
```

### Default Roles

The system comes with three predefined roles:
- **admin**: Full system access
- **producer**: Can send messages to queues
- **consumer**: Can receive messages from queues

## Authentication Flow

### User Registration
```
POST /account/signup
{
  "email": "user@example.com",
  "password": "securepassword",
  "name": "User Name"
}
```

### User Login
```
POST /account/signin
{
  "email": "user@example.com",
  "password": "securepassword"
}

Response:
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-01-01T01:00:00Z"
}
```

### JWT Token Structure

Access tokens include:
```json
{
  "uid": "user_id",
  "email": "user@example.com",
  "roles": ["producer", "consumer"],
  "exp": 1704067200,
  "iat": 1704063600,
  "nbf": 1704063600
}
```

## RBAC System

### Role Management

#### Create Role
```
POST /rbac/roles
{
  "role_name": "queue_manager"
}
```

#### List Roles
```
GET /rbac/roles
```

#### Update Role
```
PUT /rbac/roles/{roleID}
{
  "role_name": "updated_name"
}
```

#### Delete Role
```
DELETE /rbac/roles/{roleID}
```

### User Role Assignment

#### Assign Role to User
```
POST /rbac/users/{userID}/roles/{roleID}
```

#### Remove Role from User
```
DELETE /rbac/users/{userID}/roles/{roleID}
```

#### Get User Roles
```
GET /rbac/users/{userID}/roles
```

### Queue Permissions

#### Set Queue Permissions for Role
```
PUT /rbac/permissions/queues/{queueID}/roles/{roleID}
{
  "can_send": true,
  "can_receive": true,
  "can_purge": false,
  "can_delete": false
}
```

#### Get Queue Permissions
```
GET /rbac/permissions/queues/{queueID}
```

#### Check User Permission
```
GET /rbac/check/queue/{queueID}/permission/{permission}

Response:
{
  "has_permission": true
}
```

## Middleware Usage

### Authentication Middleware

Validates JWT tokens and extracts user information:

```go
import "github.com/marsolab/plainq/internal/server/middleware"

// Apply to routes that require authentication
router.Use(middleware.AuthenticateJWT(tokenManager))
```

### Role-Based Authorization

Requires specific roles:

```go
// Require admin role
router.Use(middleware.RequireAdmin())

// Require any of the specified roles
router.Use(middleware.RequireRoles("admin", "manager"))
```

### Queue Permission Middleware

Checks queue-specific permissions:

```go
// Require send permission for the queue
router.Use(middleware.RequireQueueSendPermission(rbacService))

// Require receive permission for the queue
router.Use(middleware.RequireQueueReceivePermission(rbacService))

// Require admin or specific permission
router.Use(middleware.RequireAdminOrPermission(rbacService, middleware.PermissionPurge))
```

## Complete Example

Here's how to protect a queue endpoint:

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/marsolab/plainq/internal/server/middleware"
    "github.com/marsolab/plainq/internal/server/service/rbac"
)

func setupRoutes(tokenManager jwtkit.TokenManager, rbacService *rbac.Service) chi.Router {
    r := chi.NewRouter()
    
    // Public routes
    r.Route("/account", func(r chi.Router) {
        r.Post("/signup", signupHandler)
        r.Post("/signin", signinHandler)
    })
    
    // Protected routes
    r.Route("/api", func(r chi.Router) {
        // Apply authentication middleware
        r.Use(middleware.AuthenticateJWT(tokenManager))
        
        // Admin-only routes
        r.Route("/admin", func(r chi.Router) {
            r.Use(middleware.RequireAdmin())
            r.Mount("/rbac", rbacService)
        })
        
        // Queue operations
        r.Route("/queues/{queueID}", func(r chi.Router) {
            // Send message - requires send permission
            r.With(middleware.RequireQueueSendPermission(rbacService)).Post("/messages", sendMessageHandler)
            
            // Receive message - requires receive permission
            r.With(middleware.RequireQueueReceivePermission(rbacService)).Get("/messages", receiveMessageHandler)
            
            // Purge queue - requires purge permission or admin
            r.With(middleware.RequireAdminOrPermission(rbacService, middleware.PermissionPurge)).Delete("/messages", purgeQueueHandler)
            
            // Delete queue - requires delete permission or admin
            r.With(middleware.RequireAdminOrPermission(rbacService, middleware.PermissionDelete)).Delete("/", deleteQueueHandler)
        })
    })
    
    return r
}
```

## Getting User Information

In handlers, you can access user information from the context:

```go
func messageHandler(w http.ResponseWriter, r *http.Request) {
    userInfo, ok := middleware.GetUserFromContext(r.Context())
    if !ok {
        // This shouldn't happen if middleware is properly applied
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    
    // Use user information
    log.Printf("User %s (%s) accessing resource", userInfo.UserID, userInfo.Email)
    
    // Check roles
    for _, role := range userInfo.Roles {
        if role == "admin" {
            // Handle admin user
            break
        }
    }
}
```

## Configuration

Authentication is controlled by these configuration options:

```go
type Config struct {
    AuthEnable             bool          // Enable/disable authentication
    AuthRegistrationEnable bool          // Allow new user registration
    AuthAccessTokenTTL     time.Duration // Access token lifetime
    AuthRefreshTokenTTL    time.Duration // Refresh token lifetime
}
```

## Security Considerations

1. **Password Hashing**: Uses secure password hashing (bcrypt/argon2)
2. **Token Security**: JWT tokens include expiration and are signed
3. **Token Revocation**: Access tokens can be denied via denylist
4. **Role Inheritance**: Admin role has all permissions
5. **Input Validation**: All inputs are validated and sanitized

## Onboarding Process

Instead of creating a default admin user, PlainQ implements a secure onboarding process:

### Initial Setup Check
When the server starts, it checks if any admin users exist. If not, the system enters "onboarding mode" where:
- Most endpoints return a `428 Precondition Required` status
- Only onboarding and health endpoints are accessible
- The client is directed to complete the initial setup

### Onboarding Endpoints

#### Check Onboarding Status
```
GET /onboarding/status

Response:
{
  "needs_onboarding": true,
  "has_admin_users": false
}
```

#### Complete Onboarding
```
POST /onboarding/complete
{
  "email": "admin@yourdomain.com",
  "password": "your-secure-password",
  "name": "Administrator"
}

Response:
{
  "admin": {
    "user_id": "01HQ...",
    "email": "admin@yourdomain.com",
    "name": "Administrator",
    "verified": true,
    "created_at": "2024-01-01T00:00:00Z"
  },
  "session": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "created_at": "2024-01-01T00:00:00Z",
    "expires_at": "2024-01-01T01:00:00Z"
  },
  "message": "Onboarding completed successfully. Welcome to PlainQ!"
}
```

### Security Features
- Only one admin can be created during onboarding
- Once onboarding is complete, the endpoints are disabled
- Strong password requirements (minimum 8 characters)
- Email validation
- The initial admin is automatically verified and assigned the admin role

## Error Handling

The system uses standard HTTP status codes:
- `401 Unauthorized`: Invalid or missing authentication
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `400 Bad Request`: Invalid input

Error responses follow this format:
```json
{
  "error": "error message",
  "code": "ERROR_CODE"
}
```

## Testing

You can test the system using curl:

```bash
# First, check if onboarding is needed
curl -X GET http://localhost:8080/onboarding/status

# If onboarding is needed, complete it
curl -X POST http://localhost:8080/onboarding/complete \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "your-secure-password",
    "name": "Administrator"
  }'

# Extract the access token from the response and use it
# For subsequent requests after onboarding
curl -X GET http://localhost:8080/rbac/roles \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# Or login with the created admin user
curl -X POST http://localhost:8080/account/signin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@yourdomain.com",
    "password": "your-secure-password"
  }'
```

This completes the authentication and RBAC implementation for PlainQ.
