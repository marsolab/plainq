# Security Architecture

Comprehensive guide to API authentication, authorization, and secrets
management.

## API Authentication

### 1. API Keys

**Use for:** Server-to-server, simple authentication, internal services

**Avoid for:** User authentication (no identity), frontend clients (exposure
risk)

**Format:**

```text
Authorization: Bearer <your-bearer-token>
X-API-Key: your-api-key-here
```

**Implementation:**

```python
def authenticate_api_key(request):
    api_key = request.headers.get('X-API-Key')
    if not api_key:
        return 401, "API key required"

    # Validate against database (hashed)
    if not validate_api_key(api_key):
        return 403, "Invalid API key"

    return get_api_key_metadata(api_key)
```

**Best practices:**

- Hash keys in database (never store plaintext)
- Support key rotation (multiple active keys)
- Scope keys to specific resources/actions
- Rate limit per API key
- Expiration dates
- Revocation capability

### 2. OAuth 2.0

**Use for:** Third-party integrations, delegated access, user authorization

**Grant types:**

#### Authorization Code Flow (Web Applications)

Most secure for web apps with backend:

```json
1. User → Client: Click "Login with Provider"
2. Client → Auth Server: Redirect to /authorize
   ?response_type=code
   &client_id=YOUR_CLIENT_ID
   &redirect_uri=https://yourapp.com/callback
   &scope=read:profile write:posts
   &state=random_string

3. User → Auth Server: Login and grant permissions

4. Auth Server → Client: Redirect to callback
   ?code=AUTHORIZATION_CODE
   &state=random_string

5. Client → Auth Server: POST /token
   {
     "grant_type": "authorization_code",
     "code": "AUTHORIZATION_CODE",
     "client_id": "YOUR_CLIENT_ID",
     "client_secret": "YOUR_CLIENT_SECRET",
     "redirect_uri": "https://yourapp.com/callback"
   }

6. Auth Server → Client:
   {
     "access_token": "eyJhbGc...",
     "refresh_token": "refresh_token_value",
     "expires_in": 3600,
     "token_type": "Bearer"
   }

7. Client → API: Authorization: Bearer eyJhbGc...
```

#### PKCE (Mobile/SPA - No Client Secret)

Authorization code flow without client secret:

```json
1. Client generates:
   code_verifier = random(43-128 chars)
   code_challenge = BASE64URL(SHA256(code_verifier))

2. Client → Auth Server: /authorize
   ?code_challenge=CODE_CHALLENGE
   &code_challenge_method=S256
   &client_id=...
   &redirect_uri=...

3. Auth Server → Client: Return authorization code

4. Client → Auth Server: /token
   {
     "grant_type": "authorization_code",
     "code": "AUTH_CODE",
     "code_verifier": "CODE_VERIFIER",
     "client_id": "CLIENT_ID",
     "redirect_uri": "..."
   }

5. Auth Server validates:
   SHA256(code_verifier) == code_challenge

6. Auth Server → Client: Return tokens
```

**Why PKCE?**

- No client secret (can't be secured in mobile/SPA)
- Protects against authorization code interception
- Required for mobile and single-page applications

#### Client Credentials (Server-to-Server)

Machine-to-machine authentication:

```json
POST /token
{
  "grant_type": "client_credentials",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "scope": "api:read api:write"
}

Response:
{
  "access_token": "eyJhbGc...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Token refresh:**

```json
POST /token
{
  "grant_type": "refresh_token",
  "refresh_token": "REFRESH_TOKEN",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET"
}
```

### 3. OpenID Connect (OIDC)

OAuth 2.0 + identity layer

**Tokens returned:**

- **access_token:** API access
- **refresh_token:** Get new access tokens
- **id_token:** JWT with user identity

**ID Token structure:**

```json
{
  "iss": "https://auth.example.com",
  "sub": "user_123456",
  "aud": "your_client_id",
  "exp": 1735689600,
  "iat": 1735686000,
  "auth_time": 1735686000,
  "nonce": "random_nonce",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://example.com/avatar.jpg"
}
```

**Standard claims:**

- `sub`: Subject (user ID)
- `name`: Full name
- `email`: Email address
- `email_verified`: Email verification status
- `picture`: Profile picture URL
- `iss`: Issuer
- `aud`: Audience (client ID)
- `exp`: Expiration time
- `iat`: Issued at time

**Discovery endpoint:**

```json
GET /.well-known/openid-configuration

Response:
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
}
```

### 4. JWT (JSON Web Tokens)

**Use for:** Stateless authentication, claims-based authorization

**Structure:** `header.payload.signature` (base64url encoded)

**Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key_id_123"
}
```

**Payload:**

```json
{
  "sub": "user_123",
  "name": "John Doe",
  "email": "john@example.com",
  "roles": ["admin", "user"],
  "exp": 1735689600,
  "iat": 1735686000,
  "iss": "https://auth.example.com",
  "aud": "https://api.example.com"
}
```

**Validation steps:**

1. **Verify signature:**

   ```python
   import jwt

   try:
       decoded = jwt.decode(
           token,
           public_key,
           algorithms=["RS256"],
           audience="https://api.example.com",
           issuer="https://auth.example.com"
       )
   except jwt.InvalidTokenError:
       return 401, "Invalid token"
   ```

1. **Check expiration:**

   ```python
   if decoded['exp'] < time.time():
       return 401, "Token expired"
   ```

1. **Validate claims:**

   ```python
   if decoded['aud'] != "https://api.example.com":
       return 401, "Invalid audience"
   ```

**Best practices:**

- Use RS256 (asymmetric) not HS256 (symmetric) for public APIs
- Short expiration (15-60 minutes)
- Include necessary claims only (minimize size)
- Don't store sensitive data in JWT (it's visible)
- Validate signature, expiration, issuer, audience

## Authorization

### Role-Based Access Control (RBAC)

**Model:** User → Roles → Permissions → Resources

**Example:**

```yaml
roles:
  admin:
    permissions:
      - users:create
      - users:read
      - users:update
      - users:delete
      - posts:*

  editor:
    permissions:
      - posts:create
      - posts:read
      - posts:update
      - users:read

  viewer:
    permissions:
      - posts:read
      - users:read

users:
  john@example.com:
    roles: [admin]
  jane@example.com:
    roles: [editor, viewer]
```

**Enforcement:**

```python
def check_permission(user, permission):
    for role in user.roles:
        if permission in role.permissions:
            return True
    return False

@require_permission('posts:create')
def create_post(request):
    # Handler code
    pass
```

**Pros:**

- Simple to understand
- Easy to manage
- Scales well for most applications

**Cons:**

- Coarse-grained (role-level, not resource-level)
- Role explosion in complex systems
- Hard to handle exceptions

### Attribute-Based Access Control (ABAC)

**Model:** User attributes + Resource attributes + Environment → Decision

**Policy example:**

```python
# Allow if user's department matches resource owner's department
policy = {
    "effect": "allow",
    "conditions": {
        "and": [
            {"user.department": {"equals": "resource.owner.department"}},
            {"user.role": {"in": ["manager", "admin"]}},
            {"environment.time": {"between": ["09:00", "17:00"]}}
        ]
    }
}
```

**Attributes:**

**User attributes:**

- `user.id`
- `user.role`
- `user.department`
- `user.location`
- `user.clearance_level`

**Resource attributes:**

- `resource.type`
- `resource.owner`
- `resource.classification`
- `resource.created_at`

**Environment attributes:**

- `environment.time`
- `environment.ip_address`
- `environment.device_type`

**Pros:**

- Fine-grained control
- Flexible policies
- Context-aware authorization

**Cons:**

- Complex to implement
- Harder to debug
- Performance overhead

### Multi-Level Authorization

**Layer 1: API Gateway (coarse-grained)**

- Validate JWT token
- Check high-level permissions (user has any access)
- Rate limiting per user

**Layer 2: Service (fine-grained)**

- Check resource-level permissions
- Verify user can access this specific resource
- Apply business rules

**Layer 3: Database (defense in depth)**

- Row-level security
- Prevent data leaks even if service compromised

**Example:**

```python
# API Gateway
def gateway_check(request):
    token = validate_jwt(request.headers['Authorization'])
    if not token:
        return 401, "Unauthorized"

    if 'posts:read' not in token.permissions:
        return 403, "Insufficient permissions"

    # Forward to service with user context
    return forward_to_service(request, user=token.sub)

# Service
def get_post(post_id, user_id):
    post = database.get_post(post_id)

    # Check resource ownership
    if post.is_private and post.author_id != user_id:
        return 403, "Forbidden"

    return post

# Database (PostgreSQL RLS)
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

CREATE POLICY posts_select_policy ON posts
FOR SELECT
USING (
    NOT is_private
    OR author_id = current_user_id()
);
```

## Edge Authentication Pattern

Authenticate at the edge, authorize in services.

```text
Client → API Gateway → Service
         ↓              ↓
      Validate JWT   Enforce resource-level
      Extract claims   authorization
      Enrich headers
```

**API Gateway responsibilities:**

1. **Validate JWT signature and expiration**
1. **Check token revocation** (if using revocation list)
1. **Extract claims** (user ID, roles, permissions)
1. **Enrich request headers** with authentication context
1. **Rate limit** per user/API key

**Headers forwarded to service:**

```text
X-User-ID: user_123
X-User-Email: user@example.com
X-User-Roles: admin,user
X-User-Permissions: posts:create,posts:read
```

**Service responsibilities:**

1. **Verify request has authentication context**
1. **Enforce resource-level permissions**
1. **Apply business rules**
1. **Log access attempts** for audit trail

## Secrets Management

### Principles

**Never commit secrets to Git:**

```bash
# Use git-secrets to prevent leaks
git secrets --install
git secrets --register-aws
```

**Rotate secrets regularly:**

- High-value secrets: 90 days
- API keys: 180 days
- Database passwords: 90 days
- Certificates: Before expiration

**Least privilege access:**

- Service accounts for applications
- Role-based access for humans
- Time-limited access where possible

**Audit secret access:**

- Who accessed what secret when
- Alert on unusual access patterns
- Automatic rotation on suspected compromise

### Tools

#### HashiCorp Vault

**Features:**

- Dynamic secrets (generated on-demand)
- Encryption as a service
- Lease management
- Multiple auth methods
- Multi-cloud support

**Usage:**

```bash
# Write secret
vault kv put secret/database/config \
  username=dbuser \
  password=supersecret

# Read secret
vault kv get secret/database/config

# Dynamic database credentials
vault read database/creds/readonly
```

**Dynamic secrets:**

```bash
# Vault generates temporary credentials
GET /database/creds/app-readonly

Response:
{
  "username": "v-token-app-readonly-9xkUfJv",
  "password": "Abc123XyZ",
  "lease_duration": 3600
}

# Credentials auto-revoked after 1 hour
```

#### AWS Secrets Manager

**Features:**

- AWS-native integration
- Automatic rotation
- RDS integration
- Cross-region replication
- Fine-grained IAM policies

**Usage:**

```python
import boto3

client = boto3.client('secretsmanager')

# Get secret
response = client.get_secret_value(SecretId='prod/database/password')
secret = json.loads(response['SecretString'])

# Automatic rotation
client.rotate_secret(
    SecretId='prod/database/password',
    RotationLambdaARN='arn:aws:lambda:...'
)
```

#### Azure Key Vault

**Features:**

- Azure-native integration
- HSM-backed keys
- Certificate management
- Managed identities support
- Soft delete and purge protection

**Usage:**

```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = SecretClient(vault_url="https://myvault.vault.azure.net/", credential=credential)

# Get secret
secret = client.get_secret("database-password")
```

### Kubernetes Secrets

**External Secrets Operator:**

Sync from external secret manager to K8s:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-secret
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: database-secret
  data:
  - secretKey: password
    remoteRef:
      key: secret/database/config
      property: password
```

**Sealed Secrets:**

Encrypt secrets in Git:

```bash
# Encrypt secret
kubeseal < secret.yaml > sealed-secret.yaml

# Commit sealed-secret.yaml to Git
# Controller decrypts in cluster
```

**Vault Agent Injector:**

Inject secrets as volume mounts:

```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "myapp"
    vault.hashicorp.com/agent-inject-secret-database: "secret/database/config"
spec:
  containers:
  - name: app
    image: myapp:latest
    # Secret mounted at /vault/secrets/database
```

## Best Practices

1. **Defense in depth:** Multiple layers of security
1. **Principle of least privilege:** Grant minimum required permissions
1. **Zero trust:** Verify every request, trust nothing
1. **Regular audits:** Review permissions, access logs, secrets
1. **MFA everywhere:** For human access to production
1. **Monitor anomalies:** Alert on unusual patterns
1. **Incident response plan:** Know what to do when compromised
1. **Security training:** Keep team educated on threats
