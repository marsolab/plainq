# API Design

Comprehensive guide to REST, GraphQL, gRPC, API versioning, and gateway
patterns.

## REST vs GraphQL vs gRPC

### Detailed Comparison

| Factor | REST | GraphQL | gRPC |
|--------|------|---------|------|
| **Protocol** | HTTP/1.1, HTTP/2 | HTTP/1.1, HTTP/2 | HTTP/2 only |
| **Format** | JSON, XML | JSON | Protocol Buffers (binary) |
| **Schema** | OpenAPI (optional) | GraphQL schema (required) | Protobuf (required) |
| **Caching** | HTTP caching (excellent) | Complex (query-based) | No built-in caching |
| **Tooling** | Universal | Growing (GraphiQL, Apollo) | Excellent (code generation) |
| **Learning Curve** | Low | Moderate | Moderate |
| **Performance** | Good | Good | Excellent (binary, multiplexing) |
| **Streaming** | Limited (SSE, long-polling) | Subscriptions | Bidirectional streaming |
| **Browser Support** | Native | Native | Requires gRPC-Web |
| **Debugging** | Easy (curl, browser) | Moderate (GraphiQL) | Harder (binary protocol) |
| **Bandwidth** | Higher (JSON overhead) | Medium (client controls) | Lower (binary, compression) |

### REST Best Practices

#### HTTP Methods Semantics

```text
GET /users          → List users (idempotent, cacheable)
GET /users/123      → Get user (idempotent, cacheable)
POST /users         → Create user (non-idempotent)
PUT /users/123      → Replace user (idempotent)
PATCH /users/123    → Update user fields (idempotent)
DELETE /users/123   → Delete user (idempotent)
```

#### Status Codes

**Success (2xx):**

- `200 OK` - Successful GET, PUT, PATCH, DELETE
- `201 Created` - Successful POST
- `202 Accepted` - Async processing started
- `204 No Content` - Successful DELETE (no body)

**Client Errors (4xx):**

- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing/invalid authentication
- `403 Forbidden` - Authenticated but not authorized
- `404 Not Found` - Resource doesn't exist
- `409 Conflict` - State conflict (duplicate, version mismatch)
- `422 Unprocessable Entity` - Validation failed
- `429 Too Many Requests` - Rate limit exceeded

**Server Errors (5xx):**

- `500 Internal Server Error` - Unexpected error
- `502 Bad Gateway` - Upstream service error
- `503 Service Unavailable` - Temporarily down
- `504 Gateway Timeout` - Upstream timeout

#### Pagination

**Cursor-based (recommended for large datasets):**

```json
GET /users?cursor=eyJ1c2VySWQiOjEyM30&limit=20

Response:
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJ1c2VySWQiOjE0M30",
    "has_more": true
  }
}
```

**Pros:**

- Handles concurrent writes correctly
- Consistent results
- Works with large offsets

**Cons:**

- Can't jump to specific page
- More complex implementation

**Offset-based (simple, use for small datasets):**

```json
GET /users?offset=20&limit=20

Response:
{
  "data": [...],
  "pagination": {
    "offset": 20,
    "limit": 20,
    "total": 1000
  }
}
```

**Pros:**

- Simple to implement
- Can jump to specific page
- Shows total count

**Cons:**

- Inconsistent with concurrent writes
- Slow for large offsets

#### HATEOAS (Hypermedia)

Include links to related resources:

```json
{
  "id": 123,
  "name": "John Doe",
  "links": {
    "self": "/users/123",
    "posts": "/users/123/posts",
    "followers": "/users/123/followers"
  }
}
```

### GraphQL Best Practices

#### Schema Design

```graphql
type User {
  id: ID!                    # Non-null ID
  email: String!             # Required field
  name: String               # Optional field
  posts(first: Int = 10): PostConnection  # Paginated
  createdAt: DateTime!
}

type Post {
  id: ID!
  title: String!
  content: String
  author: User!              # Relationship
  publishedAt: DateTime
}

# Connection pattern for pagination
type PostConnection {
  edges: [PostEdge!]!
  pageInfo: PageInfo!
}

type PostEdge {
  node: Post!
  cursor: String!
}

type PageInfo {
  hasNextPage: Boolean!
  hasPreviousPage: Boolean!
  startCursor: String
  endCursor: String
}
```

#### Pagination (Relay specification)

```graphql
query {
  user(id: "123") {
    posts(first: 10, after: "cursor") {
      edges {
        node {
          id
          title
        }
        cursor
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
```

#### Complexity Limits

Prevent resource exhaustion queries:

```graphql
# Dangerous query
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              # Exponential growth!
            }
          }
        }
      }
    }
  }
}
```

**Protection strategies:**

1. **Query depth limit:** Max 7 levels deep
1. **Query complexity:** Assign cost to fields, limit total cost
1. **Timeout:** Kill queries exceeding time limit
1. **Rate limiting:** Limit queries per user/API key

#### DataLoader Pattern (N+1 Problem)

**Problem:**

```javascript
// N+1 query problem
posts.forEach(post => {
  // 1 query per post!
  const author = database.getUser(post.authorId);
});
```

**Solution with DataLoader:**

```javascript
const userLoader = new DataLoader(async (userIds) => {
  // Single batched query
  const users = await database.getUsersByIds(userIds);
  return userIds.map(id => users.find(u => u.id === id));
});

posts.forEach(async (post) => {
  // Automatically batched
  const author = await userLoader.load(post.authorId);
});
```

### gRPC Best Practices

#### Service Definition

```protobuf
syntax = "proto3";

service UserService {
  // Unary RPC
  rpc GetUser (GetUserRequest) returns (User);

  // Server streaming
  rpc ListUsers (ListUsersRequest) returns (stream User);

  // Client streaming
  rpc CreateUsers (stream CreateUserRequest) returns (CreateUsersResponse);

  // Bidirectional streaming
  rpc Chat (stream ChatMessage) returns (stream ChatMessage);
}

message GetUserRequest {
  string user_id = 1;
}

message User {
  string id = 1;
  string email = 2;
  string name = 3;
  int64 created_at = 4;
}
```

#### Streaming Use Cases

**Server streaming:**

- Large result sets (paginated data)
- Real-time updates (stock prices, metrics)
- File downloads

**Client streaming:**

- File uploads
- Batch inserts
- Continuous sensor data

**Bidirectional streaming:**

- Chat applications
- Real-time collaboration
- Game servers

#### Error Handling

```go
// Return gRPC status codes
import "google.golang.org/grpc/status"
import "google.golang.org/grpc/codes"

func (s *server) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
    user, err := s.db.GetUser(req.UserId)
    if err == sql.ErrNoRows {
        return nil, status.Errorf(codes.NotFound, "user not found: %v", req.UserId)
    }
    if err != nil {
        return nil, status.Errorf(codes.Internal, "database error: %v", err)
    }
    return user, nil
}
```

**gRPC status codes:**

- `OK` - Success
- `INVALID_ARGUMENT` - Invalid request
- `NOT_FOUND` - Resource not found
- `ALREADY_EXISTS` - Duplicate resource
- `PERMISSION_DENIED` - Authorization failed
- `UNAUTHENTICATED` - Authentication required
- `RESOURCE_EXHAUSTED` - Rate limit exceeded
- `INTERNAL` - Server error
- `UNAVAILABLE` - Service unavailable
- `DEADLINE_EXCEEDED` - Timeout

## API Versioning Strategies

### 1. URI Path Versioning

```text
https://api.example.com/v1/users
https://api.example.com/v2/users
```

**Pros:**

- Clear and explicit
- Easy to route and cache
- Simple to understand

**Cons:**

- Multiple endpoints to maintain
- Violates REST principles (resource has multiple URIs)

**Best for:** Public APIs, simple versioning

### 2. Query Parameter

```text
https://api.example.com/users?version=2
https://api.example.com/users?api-version=2.0
```

**Pros:**

- Clean URLs
- Optional parameter (default version)
- Easy to test

**Cons:**

- Easy to forget
- Caching complexity
- Not RESTful

**Best for:** Internal APIs, optional versioning

### 3. Header Versioning

```text
GET /users
Accept: application/vnd.example.v2+json

or

GET /users
X-API-Version: 2
```

**Pros:**

- Clean URLs
- Follows HTTP standards
- Doesn't pollute URI

**Cons:**

- Less visible
- Harder to test manually (can't just paste URL)
- Not cached differently by CDN

**Best for:** APIs with complex content negotiation

### 4. Content Negotiation

```text
GET /users
Accept: application/vnd.example.users.v2+json
```

**Pros:**

- Most RESTful approach
- Granular versioning per resource
- Standard HTTP mechanism

**Cons:**

- Most complex
- Less tooling support
- Overkill for most APIs

**Best for:** Mature APIs with multiple representations

### Backward Compatibility

**Rules for non-breaking changes:**

- ✓ Add new fields (with defaults)
- ✓ Add new endpoints
- ✓ Make required fields optional
- ✓ Expand enum values
- ✓ Loosen validation rules

**Breaking changes require new version:**

- ✗ Remove fields
- ✗ Rename fields
- ✗ Change field types
- ✗ Make optional fields required
- ✗ Remove enum values
- ✗ Tighten validation rules

**Deprecation process:**

1. **Announce:** Document deprecated fields/endpoints
1. **Warning headers:** `Warning: 299 - "Deprecated, use /v2/users instead"`
1. **Grace period:** 6-12 months minimum
1. **Monitor usage:** Track deprecated endpoint usage
1. **Sunset header:** `Sunset: Sat, 31 Dec 2024 23:59:59 GMT`
1. **Remove:** After grace period, return 410 Gone

## API Gateway Patterns

### Responsibilities

**Authentication:**

- Validate JWT tokens
- Check API keys
- OAuth 2.0 token introspection
- Rate limiting per user/key

**Request Routing:**

- Path-based routing
- Header-based routing
- Weighted routing (A/B testing)
- Canary deployments

**Protocol Translation:**

- REST to gRPC
- HTTP to WebSocket
- GraphQL to microservices

**Response Aggregation:**

- Combine multiple service responses
- Backend for Frontend (BFF) pattern
- Reduce client round-trips

**Cross-Cutting Concerns:**

- SSL termination
- Request/response logging
- CORS handling
- Rate limiting
- IP whitelisting/blacklisting

### Architecture Patterns

#### 1. Single Gateway

One gateway for all clients.

```text
[Clients] → [API Gateway] → [Services]
```

**Pros:**

- Simple architecture
- Centralized control
- Easy to secure

**Cons:**

- Single point of failure
- Scaling bottleneck
- One-size-fits-all for different clients

**Use for:** Small applications, internal APIs

#### 2. Backend for Frontend (BFF)

One gateway per client type.

```text
[Web App] → [Web BFF] → [Services]
[Mobile App] → [Mobile BFF] → [Services]
[Partner API] → [Partner BFF] → [Services]
```

**Pros:**

- Optimized for each client
- Independent evolution
- Client-specific logic

**Cons:**

- Code duplication
- More operational complexity
- Multiple gateways to maintain

**Use for:** Multiple client types with different needs

#### 3. API Aggregator

Separate gateway and aggregation layers.

```text
[Clients] → [API Gateway] → [Aggregator Service] → [Services]
```

**Pros:**

- Separation of concerns
- Gateway focuses on routing/auth
- Aggregator focuses on composition

**Cons:**

- Additional network hop
- More complexity
- Higher latency

**Use for:** Complex aggregation logic

### Popular Tools

**Kong:**

- Lua-based plugins
- Extensive plugin ecosystem
- Enterprise features
- Database-backed or DB-less mode

**AWS API Gateway:**

- Serverless, auto-scaling
- Lambda integration
- AWS-native (Cognito, CloudWatch)
- Usage plans and API keys

**Azure API Management:**

- Enterprise-focused
- Policy-based transformation
- Developer portal
- Azure integration

**Traefik:**

- Kubernetes-native
- Dynamic configuration
- Modern, cloud-native
- Built-in Let's Encrypt

**Envoy:**

- Service mesh foundation
- High performance (C++)
- Advanced routing
- Observability built-in

## Authentication Flows

### OAuth 2.0 Authorization Code Flow

Secure flow for web applications.

```bash
1. User → Client: Click "Login"
2. Client → Auth Server: Redirect to /authorize?client_id=...&redirect_uri=...
3. User → Auth Server: Enter credentials
4. Auth Server → Client: Redirect to redirect_uri?code=ABC
5. Client → Auth Server: POST /token with code=ABC&client_secret=XYZ
6. Auth Server → Client: Return access_token + refresh_token
7. Client → API: Request with Authorization: Bearer {access_token}
```

### OAuth 2.0 PKCE (for mobile/SPA)

Authorization code flow without client secret.

```text
1. Client generates code_verifier (random string)
2. Client generates code_challenge = SHA256(code_verifier)
3. Client → Auth Server: /authorize?code_challenge=...&code_challenge_method=S256
4. Auth Server → Client: Return authorization code
5. Client → Auth Server: /token with code=...&code_verifier=...
6. Auth Server validates SHA256(code_verifier) == code_challenge
7. Auth Server → Client: Return access_token
```

### OpenID Connect (OIDC)

OAuth 2.0 + identity information.

```text
Tokens returned:
- access_token: API access
- refresh_token: Get new access tokens
- id_token: JWT with user identity
```

**ID Token claims:**

```json
{
  "iss": "https://auth.example.com",
  "sub": "user123",
  "aud": "client-id",
  "exp": 1735689600,
  "iat": 1735686000,
  "email": "user@example.com",
  "name": "John Doe"
}
```

## Best Practices

1. **Version from day one:** Don't wait until you need to break things
1. **Document everything:** OpenAPI for REST, schema for GraphQL
1. **Rate limit aggressively:** Protect services from abuse
1. **Use HTTPS everywhere:** No exceptions
1. **Validate inputs:** Never trust client data
1. **Return meaningful errors:** Help developers debug
1. **Monitor API usage:** Track endpoints, error rates, latency
1. **Design for backward compatibility:** Minimize breaking changes
