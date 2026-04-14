# Bun Runtime Reference

## Overview

Bun is an all-in-one JavaScript runtime, package manager, bundler, and test
runner. Use it as the foundation for fast development and builds.

## Quick Setup

```bash
# Install Bun
curl -fsSL https://bun.sh/install | bash

# Create new project
bun init

# Install dependencies (10x faster than npm)
bun install

# Run TypeScript directly
bun run src/index.ts

# Run tests
bun test

# Build for production
bun build ./src/index.ts --outdir ./dist
```

## Architecture Patterns

### Fetch API Server Model

Bun's HTTP server uses the Web Fetch standard:

```typescript
// server.ts
const server = Bun.serve({
  port: 3000,
  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);

    // Route handling
    if (url.pathname === '/api/health') {
      return Response.json({ status: 'ok', timestamp: Date.now() });
    }

    if (url.pathname === '/api/users' && req.method === 'POST') {
      const body = await req.json();
      // Handle user creation
      return Response.json({ id: crypto.randomUUID(), ...body }, { status: 201 });
    }

    // 404 for unknown routes
    return new Response('Not Found', { status: 404 });
  },

  // Error handling
  error(error: Error) {
    console.error('Server error:', error);
    return new Response('Internal Server Error', { status: 500 });
  },
});

console.log(`Server running at http://localhost:${server.port}`);
```

### Multi-Core Scaling with Cluster

Use Node's cluster module for CPU-bound tasks:

```typescript
// cluster-server.ts
import cluster from 'node:cluster';
import { cpus } from 'node:os';

const numCPUs = cpus().length;

if (cluster.isPrimary) {
  console.log(`Primary ${process.pid} is running`);
  console.log(`Forking ${numCPUs} workers...`);

  // Fork workers
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }

  // Handle worker exit
  cluster.on('exit', (worker, code, signal) => {
    console.log(`Worker ${worker.process.pid} died (${signal || code})`);
    console.log('Starting a new worker...');
    cluster.fork(); // Auto-restart
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    for (const id in cluster.workers) {
      cluster.workers[id]?.kill();
    }
  });
} else {
  // Workers share the same port
  const server = Bun.serve({
    port: 3000,
    reusePort: true, // Critical for load balancing on Linux
    fetch(req) {
      return new Response(`Hello from worker ${process.pid}`);
    },
  });

  console.log(`Worker ${process.pid} started on port ${server.port}`);
}
```

### Dependency Injection Pattern for Testing

Structure code for testability:

```typescript
// types/dependencies.ts
export interface Database {
  query<T>(sql: string, params?: unknown[]): Promise<T[]>;
  execute(sql: string, params?: unknown[]): Promise<void>;
}

export interface Cache {
  get<T>(key: string): Promise<T | null>;
  set<T>(key: string, value: T, ttlSeconds?: number): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface Logger {
  info(message: string, meta?: Record<string, unknown>): void;
  error(message: string, error?: Error, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
}

export interface Dependencies {
  db: Database;
  cache: Cache;
  logger: Logger;
}

// services/user-service.ts
export function createUserService(deps: Dependencies) {
  const { db, cache, logger } = deps;

  return {
    async getUser(id: string) {
      // Try cache first
      const cached = await cache.get<User>(`user:${id}`);
      if (cached) {
        logger.info('Cache hit for user', { id });
        return cached;
      }

      // Query database
      logger.info('Cache miss, querying database', { id });
      const [user] = await db.query<User>('SELECT * FROM users WHERE id = ?', [id]);

      if (user) {
        await cache.set(`user:${id}`, user, 300); // 5 min TTL
      }

      return user ?? null;
    },

    async createUser(data: CreateUserInput) {
      const id = crypto.randomUUID();
      await db.execute(
        'INSERT INTO users (id, email, name) VALUES (?, ?, ?)',
        [id, data.email, data.name]
      );
      logger.info('User created', { id, email: data.email });
      return { id, ...data };
    },
  };
}

// In production
import { createPgDatabase } from './infra/postgres';
import { createRedisCache } from './infra/redis';
import { createPinoLogger } from './infra/pino';

const deps: Dependencies = {
  db: createPgDatabase(process.env.DATABASE_URL!),
  cache: createRedisCache(process.env.REDIS_URL!),
  logger: createPinoLogger(),
};

const userService = createUserService(deps);

// In tests
import { describe, test, expect, mock } from 'bun:test';

describe('UserService', () => {
  const mockDeps: Dependencies = {
    db: {
      query: mock(() => Promise.resolve([])),
      execute: mock(() => Promise.resolve()),
    },
    cache: {
      get: mock(() => Promise.resolve(null)),
      set: mock(() => Promise.resolve()),
      delete: mock(() => Promise.resolve()),
    },
    logger: {
      info: mock(() => {}),
      error: mock(() => {}),
      warn: mock(() => {}),
    },
  };

  test('getUser returns null for non-existent user', async () => {
    const service = createUserService(mockDeps);
    const user = await service.getUser('non-existent');
    expect(user).toBeNull();
  });

  test('getUser uses cache when available', async () => {
    const cachedUser = { id: '1', name: 'Test', email: 'test@example.com' };
    mockDeps.cache.get = mock(() => Promise.resolve(cachedUser));

    const service = createUserService(mockDeps);
    const user = await service.getUser('1');

    expect(user).toEqual(cachedUser);
    expect(mockDeps.db.query).not.toHaveBeenCalled();
  });
});
```

## Performance Optimization

### Async Efficiency

Leverage Bun's parallel I/O:

```typescript
// Good: Parallel operations
async function fetchAllData() {
  const [users, products, orders] = await Promise.all([
    fetch('/api/users').then(r => r.json()),
    fetch('/api/products').then(r => r.json()),
    fetch('/api/orders').then(r => r.json()),
  ]);
  return { users, products, orders };
}

// Good: Streaming large responses
async function streamLargeFile(req: Request): Promise<Response> {
  const file = Bun.file('./large-data.json');
  return new Response(file.stream(), {
    headers: { 'Content-Type': 'application/json' },
  });
}

// Good: Concurrent file processing
async function processFiles(paths: string[]) {
  return Promise.all(
    paths.map(async (path) => {
      const file = Bun.file(path);
      const text = await file.text();
      return processContent(text);
    })
  );
}

// Bad: Sequential when parallel is possible
async function fetchSequential() {
  const users = await fetch('/api/users').then(r => r.json());
  const products = await fetch('/api/products').then(r => r.json()); // Waits for users
  return { users, products };
}
```

### Built-in Bundling

```typescript
// build.ts
await Bun.build({
  entrypoints: ['./src/index.ts'],
  outdir: './dist',
  target: 'bun', // or 'browser', 'node'
  minify: true,
  sourcemap: 'external',
  splitting: true, // Code splitting for multiple entrypoints
  external: ['sharp'], // Don't bundle native modules
});
```

### HTTP/2 for Asset Serving

```typescript
// Use HTTP/2 for multiplexing
import { createServer } from 'node:http2';
import { readFileSync } from 'node:fs';

const server = createServer({
  key: readFileSync('./certs/key.pem'),
  cert: readFileSync('./certs/cert.pem'),
});

server.on('stream', (stream, headers) => {
  const path = headers[':path'];

  // Server push for critical assets
  if (path === '/') {
    stream.pushStream({ ':path': '/styles.css' }, (err, pushStream) => {
      if (!err) {
        pushStream.respond({ ':status': 200, 'content-type': 'text/css' });
        pushStream.end(readFileSync('./public/styles.css'));
      }
    });
  }

  stream.respond({ ':status': 200 });
  stream.end('<html>...</html>');
});

server.listen(443);
```

## Security Hardening

### OWASP Best Practices

```typescript
// security/middleware.ts
import { createHash, randomBytes } from 'node:crypto';

// Input validation
function validateInput<T>(schema: ZodSchema<T>, data: unknown): T {
  const result = schema.safeParse(data);
  if (!result.success) {
    throw new ValidationError(result.error.issues);
  }
  return result.data;
}

// CSRF token generation
function generateCsrfToken(): string {
  return randomBytes(32).toString('hex');
}

function verifyCsrfToken(token: string, expected: string): boolean {
  if (!token || !expected) return false;
  // Timing-safe comparison
  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expected);
  if (tokenBuffer.length !== expectedBuffer.length) return false;
  return crypto.timingSafeEqual(tokenBuffer, expectedBuffer);
}

// Rate limiting
const rateLimits = new Map<string, { count: number; resetAt: number }>();

function checkRateLimit(ip: string, limit = 100, windowMs = 60000): boolean {
  const now = Date.now();
  const record = rateLimits.get(ip);

  if (!record || record.resetAt < now) {
    rateLimits.set(ip, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (record.count >= limit) {
    return false;
  }

  record.count++;
  return true;
}

// Secure headers middleware
function securityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);

  // Content Security Policy
  headers.set('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
  ].join('; '));

  // Other security headers
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

  if (process.env.NODE_ENV === 'production') {
    headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// Secure server
const server = Bun.serve({
  port: 3000,
  async fetch(req) {
    // Rate limiting
    const ip = req.headers.get('x-forwarded-for') || 'unknown';
    if (!checkRateLimit(ip)) {
      return new Response('Too Many Requests', { status: 429 });
    }

    // CSRF check for mutations
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
      const csrfToken = req.headers.get('x-csrf-token');
      const sessionToken = getCsrfFromSession(req); // Implement based on session store
      if (!verifyCsrfToken(csrfToken || '', sessionToken || '')) {
        return new Response('Invalid CSRF token', { status: 403 });
      }
    }

    // Handle request...
    const response = await handleRequest(req);

    // Add security headers
    return securityHeaders(response);
  },
});
```

### HTTPS/TLS Configuration

```typescript
// server-tls.ts
import { readFileSync } from 'node:fs';

const server = Bun.serve({
  port: 443,
  tls: {
    key: readFileSync('./certs/key.pem'),
    cert: readFileSync('./certs/cert.pem'),
    // Optional: CA chain
    ca: readFileSync('./certs/ca.pem'),
    // Minimum TLS 1.2
    minVersion: 'TLSv1.2',
  },
  fetch(req) {
    return new Response('Secure!');
  },
});

// Redirect HTTP to HTTPS
Bun.serve({
  port: 80,
  fetch(req) {
    const url = new URL(req.url);
    url.protocol = 'https:';
    url.port = '443';
    return Response.redirect(url.toString(), 301);
  },
});
```

### Secrets Management

```typescript
// config/env.ts
import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),
  JWT_SECRET: z.string().min(32),
  API_KEY: z.string().min(16),
});

// Parse and validate at startup
export const env = envSchema.parse(process.env);

// Never log secrets
const safeEnv = { ...env };
delete (safeEnv as any).JWT_SECRET;
delete (safeEnv as any).API_KEY;
console.log('Environment:', safeEnv);
```

## Observability

### Structured Logging with Pino

```typescript
// logger.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level: (label) => ({ level: label }),
    bindings: (bindings) => ({
      pid: bindings.pid,
      host: bindings.hostname,
      service: 'my-app',
      version: process.env.npm_package_version,
    }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  // Add request ID to all logs
  mixin() {
    return { requestId: getRequestId() };
  },
});

// Request logging middleware
export function requestLogger(req: Request, start: number) {
  const duration = Date.now() - start;
  const url = new URL(req.url);

  logger.info({
    type: 'request',
    method: req.method,
    path: url.pathname,
    query: url.search,
    userAgent: req.headers.get('user-agent'),
    duration,
    status: 200, // Update with actual status
  }, `${req.method} ${url.pathname}`);
}

// Error logging
export function logError(error: Error, context?: Record<string, unknown>) {
  logger.error({
    type: 'error',
    error: {
      name: error.name,
      message: error.message,
      stack: error.stack,
    },
    ...context,
  }, error.message);
}
```

### OpenTelemetry Integration

```typescript
// tracing.ts
import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { Resource } from '@opentelemetry/resources';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

const sdk = new NodeSDK({
  resource: new Resource({
    [SemanticResourceAttributes.SERVICE_NAME]: 'my-bun-app',
    [SemanticResourceAttributes.SERVICE_VERSION]: '1.0.0',
  }),
  traceExporter: new OTLPTraceExporter({
    url: process.env.OTEL_EXPORTER_OTLP_ENDPOINT || 'http://localhost:4318/v1/traces',
  }),
  instrumentations: [getNodeAutoInstrumentations()],
});

sdk.start();

// Graceful shutdown
process.on('SIGTERM', () => {
  sdk.shutdown()
    .then(() => console.log('Tracing terminated'))
    .catch((error) => console.log('Error terminating tracing', error))
    .finally(() => process.exit(0));
});
```

### Health Check Endpoint

```typescript
// health.ts
interface HealthCheck {
  name: string;
  check: () => Promise<boolean>;
}

const healthChecks: HealthCheck[] = [
  {
    name: 'database',
    check: async () => {
      try {
        await db.query('SELECT 1');
        return true;
      } catch {
        return false;
      }
    },
  },
  {
    name: 'redis',
    check: async () => {
      try {
        await cache.ping();
        return true;
      } catch {
        return false;
      }
    },
  },
];

async function getHealthStatus() {
  const results = await Promise.all(
    healthChecks.map(async ({ name, check }) => ({
      name,
      healthy: await check().catch(() => false),
    }))
  );

  const healthy = results.every(r => r.healthy);

  return {
    status: healthy ? 'healthy' : 'unhealthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: results,
  };
}

// In your server
if (url.pathname === '/health') {
  const health = await getHealthStatus();
  return Response.json(health, {
    status: health.status === 'healthy' ? 200 : 503,
  });
}

// Kubernetes-style probes
if (url.pathname === '/healthz') {
  return new Response('OK'); // Liveness
}

if (url.pathname === '/readyz') {
  const health = await getHealthStatus();
  return new Response(health.status === 'healthy' ? 'OK' : 'NOT READY', {
    status: health.status === 'healthy' ? 200 : 503,
  });
}
```

## Testing with Bun

### Built-in Test Runner

```typescript
// user.test.ts
import { describe, test, expect, beforeAll, afterAll, mock, spyOn } from 'bun:test';

describe('User API', () => {
  let server: ReturnType<typeof Bun.serve>;

  beforeAll(() => {
    server = Bun.serve({
      port: 0, // Random available port
      fetch: app.fetch,
    });
  });

  afterAll(() => {
    server.stop();
  });

  test('GET /api/users returns users', async () => {
    const response = await fetch(`http://localhost:${server.port}/api/users`);
    expect(response.status).toBe(200);

    const data = await response.json();
    expect(Array.isArray(data)).toBe(true);
  });

  test('POST /api/users creates user', async () => {
    const response = await fetch(`http://localhost:${server.port}/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Test', email: 'test@example.com' }),
    });

    expect(response.status).toBe(201);
    const user = await response.json();
    expect(user).toHaveProperty('id');
    expect(user.name).toBe('Test');
  });

  test('handles validation errors', async () => {
    const response = await fetch(`http://localhost:${server.port}/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: '' }), // Missing email
    });

    expect(response.status).toBe(400);
  });
});

// Mocking example
describe('UserService with mocks', () => {
  test('calls database with correct query', async () => {
    const mockQuery = mock(() => Promise.resolve([{ id: '1', name: 'Test' }]));
    const db = { query: mockQuery };

    const service = createUserService({ db, cache: mockCache, logger: mockLogger });
    await service.getUser('1');

    expect(mockQuery).toHaveBeenCalledWith(
      'SELECT * FROM users WHERE id = ?',
      ['1']
    );
  });
});
```

### Running Tests

```bash
# Run all tests
bun test

# Watch mode
bun test --watch

# Run specific file
bun test user.test.ts

# With coverage
bun test --coverage

# Timeout for slow tests
bun test --timeout 10000
```

## TypeScript Configuration

```json
// tsconfig.json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "types": ["bun-types"],
    "strict": true,
    "skipLibCheck": true,
    "noEmit": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "react-jsx",
    "jsxImportSource": "react",
    "paths": {
      "@/*": ["./src/*"]
    }
  },
  "include": ["src/**/*", "tests/**/*"],
  "exclude": ["node_modules", "dist"]
}
```

## Package Manager Features

```bash
# Install all dependencies
bun install

# Add dependency
bun add zod

# Add dev dependency
bun add -d vitest

# Remove dependency
bun remove lodash

# Update all
bun update

# Run package binary
bunx eslint .

# Run script from package.json
bun run build
bun run dev

# Link local package
bun link ../my-library
```

## Common Issues & Solutions

| Issue | Solution |
|-------|----------|
| Native addon doesn't work | Check Bun compatibility, file issue if needed |
| Memory usage high | Use streams for large data, check for leaks |
| Package not found | Verify in bun.lockb, try `bun install --force` |
| TypeScript errors | Ensure bun-types in tsconfig types array |
| Tests fail but work in Node | Check for Node-specific APIs, use bun:test |
| Build output too large | Enable minify, check externals configuration |
