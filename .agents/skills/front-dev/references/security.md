# Security Reference

## Overview

Security best practices for Astro + React/Preact applications. Most security is
handled at the Astro/server level, but React components need awareness too.

## XSS Prevention

### Astro Auto-Escaping

Astro automatically escapes content by default:

```astro
---
// src/pages/post.astro
const userContent = "<script>alert('xss')</script>";
---

<!-- Safe: Auto-escaped -->
<p>{userContent}</p>
<!-- Renders: &lt;script&gt;alert('xss')&lt;/script&gt; -->

<!-- Dangerous: set:html bypasses escaping -->
<p set:html={userContent}></p>
<!-- Only use with trusted/sanitized content -->
```

### React Auto-Escaping

React/JSX also auto-escapes by default:

```tsx
function Comment({ content }: { content: string }) {
  // Safe: Auto-escaped
  return <p>{content}</p>;
}

// Dangerous: dangerouslySetInnerHTML
function UnsafeComment({ html }: { html: string }) {
  // Only use with sanitized content!
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

### Sanitizing User HTML

When you must render user HTML, sanitize it:

```bash
bun add dompurify
bun add -d @types/dompurify
```

```tsx
// lib/sanitize.ts
import DOMPurify from 'dompurify';

// Configure allowed tags and attributes
const config = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'target', 'rel'],
  ALLOW_DATA_ATTR: false,
};

export function sanitizeHtml(dirty: string): string {
  return DOMPurify.sanitize(dirty, config);
}

// For links, ensure safe protocols
export function sanitizeUrl(url: string): string {
  const allowed = ['http:', 'https:', 'mailto:'];
  try {
    const parsed = new URL(url);
    if (allowed.includes(parsed.protocol)) {
      return url;
    }
  } catch {
    // Invalid URL
  }
  return '#';
}

// Usage in React
function RichContent({ html }: { html: string }) {
  const sanitized = sanitizeHtml(html);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// Usage in Astro
---
import { sanitizeHtml } from '@/lib/sanitize';
const safeHtml = sanitizeHtml(userContent);
---
<div set:html={safeHtml}></div>
```

### Handling User-Provided URLs

```tsx
// components/UserLink.tsx
import { sanitizeUrl } from '@/lib/sanitize';

interface UserLinkProps {
  href: string;
  children: React.ReactNode;
}

export function UserLink({ href, children }: UserLinkProps) {
  const safeHref = sanitizeUrl(href);

  return (
    <a
      href={safeHref}
      target="_blank"
      rel="noopener noreferrer" // Prevent opener access
    >
      {children}
    </a>
  );
}
```

## CSRF Protection

### Token-Based CSRF Protection

```typescript
// lib/csrf.ts
import { randomBytes, timingSafeEqual } from 'crypto';

// Generate token
export function generateCsrfToken(): string {
  return randomBytes(32).toString('hex');
}

// Verify token (timing-safe)
export function verifyCsrfToken(token: string, expected: string): boolean {
  if (!token || !expected || token.length !== expected.length) {
    return false;
  }

  const tokenBuffer = Buffer.from(token);
  const expectedBuffer = Buffer.from(expected);

  return timingSafeEqual(tokenBuffer, expectedBuffer);
}
```

```astro
---
// src/pages/form.astro
import { generateCsrfToken } from '@/lib/csrf';

const csrfToken = generateCsrfToken();
// Store in session/cookie for verification
Astro.cookies.set('csrf', csrfToken, {
  httpOnly: true,
  secure: import.meta.env.PROD,
  sameSite: 'strict',
  path: '/',
});
---

<form method="POST" action="/api/submit">
  <input type="hidden" name="csrf" value={csrfToken} />
  <!-- form fields -->
  <button type="submit">Submit</button>
</form>
```

```typescript
// src/pages/api/submit.ts
import type { APIRoute } from 'astro';
import { verifyCsrfToken } from '@/lib/csrf';

export const POST: APIRoute = async ({ request, cookies }) => {
  const formData = await request.formData();
  const token = formData.get('csrf')?.toString();
  const expected = cookies.get('csrf')?.value;

  if (!verifyCsrfToken(token || '', expected || '')) {
    return new Response('Invalid CSRF token', { status: 403 });
  }

  // Process form...
  return new Response('Success');
};
```

### CSRF with React Forms

```tsx
// components/SecureForm.tsx
import { useEffect, useState } from 'react';

export function SecureForm() {
  const [csrfToken, setCsrfToken] = useState('');

  useEffect(() => {
    // Fetch CSRF token from API
    fetch('/api/csrf')
      .then(r => r.json())
      .then(data => setCsrfToken(data.token));
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();

    const response = await fetch('/api/submit', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken, // Send in header
      },
      body: JSON.stringify({ /* data */ }),
    });

    // Handle response
  }

  return (
    <form onSubmit={handleSubmit}>
      {/* Form fields */}
      <button type="submit" disabled={!csrfToken}>Submit</button>
    </form>
  );
}
```

## Content Security Policy

### Configure CSP Headers

```typescript
// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';

export const onRequest = defineMiddleware(async (context, next) => {
  const response = await next();

  // Only modify HTML responses
  if (response.headers.get('content-type')?.includes('text/html')) {
    const nonce = crypto.randomUUID();

    // Set CSP header
    response.headers.set('Content-Security-Policy', [
      `default-src 'self'`,
      `script-src 'self' 'nonce-${nonce}'`,
      `style-src 'self' 'unsafe-inline'`, // Needed for Tailwind
      `img-src 'self' data: https:`,
      `font-src 'self'`,
      `connect-src 'self' https://api.example.com`,
      `frame-ancestors 'none'`,
      `form-action 'self'`,
      `base-uri 'self'`,
    ].join('; '));

    // Add other security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '1; mode=block');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    if (import.meta.env.PROD) {
      response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
  }

  return response;
});
```

### CSP with Inline Scripts (Nonces)

```astro
---
// src/layouts/BaseLayout.astro
const nonce = crypto.randomUUID();
---
<html>
<head>
  <!-- Inline script with nonce -->
  <script nonce={nonce}>
    // Theme initialization
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.classList.toggle('dark', theme === 'dark');
  </script>
</head>
<body>
  <slot />
</body>
</html>
```

## Environment Variables & Secrets

### Server-Only Secrets

```typescript
// astro.config.mjs - Server secrets are NEVER exposed to client
// Access with: import.meta.env.SECRET_API_KEY

// .env
SECRET_API_KEY=sk-xxxx          # Server only (SECRET_ prefix)
PUBLIC_API_URL=https://api.com  # Exposed to client (PUBLIC_ prefix)
```

```typescript
// src/pages/api/data.ts
import type { APIRoute } from 'astro';

export const GET: APIRoute = async () => {
  // Safe: Server-side only
  const apiKey = import.meta.env.SECRET_API_KEY;

  const response = await fetch('https://api.example.com/data', {
    headers: { Authorization: `Bearer ${apiKey}` },
  });

  return new Response(JSON.stringify(await response.json()), {
    headers: { 'Content-Type': 'application/json' },
  });
};
```

### Validate Environment at Startup

```typescript
// src/lib/env.ts
import { z } from 'zod';

const envSchema = z.object({
  // Public (exposed to client)
  PUBLIC_API_URL: z.string().url(),
  PUBLIC_SITE_URL: z.string().url(),

  // Server-only secrets
  SECRET_DATABASE_URL: z.string().url(),
  SECRET_API_KEY: z.string().min(20),
  SECRET_JWT_SECRET: z.string().min(32),
});

// Validate and export
export const env = envSchema.parse({
  PUBLIC_API_URL: import.meta.env.PUBLIC_API_URL,
  PUBLIC_SITE_URL: import.meta.env.PUBLIC_SITE_URL,
  SECRET_DATABASE_URL: import.meta.env.SECRET_DATABASE_URL,
  SECRET_API_KEY: import.meta.env.SECRET_API_KEY,
  SECRET_JWT_SECRET: import.meta.env.SECRET_JWT_SECRET,
});

// Type-safe access
// import { env } from '@/lib/env';
// env.SECRET_API_KEY
```

## Authentication

### Session-Based Auth

```typescript
// lib/auth.ts
import { createHash, randomBytes } from 'crypto';

interface Session {
  userId: string;
  expiresAt: Date;
}

// In-memory store (use Redis/DB in production)
const sessions = new Map<string, Session>();

export function createSession(userId: string): string {
  const sessionId = randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

  sessions.set(sessionId, { userId, expiresAt });

  return sessionId;
}

export function getSession(sessionId: string): Session | null {
  const session = sessions.get(sessionId);

  if (!session) return null;
  if (session.expiresAt < new Date()) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

export function deleteSession(sessionId: string): void {
  sessions.delete(sessionId);
}

// Password hashing
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex');
  const hash = createHash('sha256')
    .update(password + salt)
    .digest('hex');
  return `${salt}:${hash}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const [salt, hash] = stored.split(':');
  const attempt = createHash('sha256')
    .update(password + salt)
    .digest('hex');
  return hash === attempt;
}
```

### Auth Middleware

```typescript
// src/middleware.ts
import { defineMiddleware } from 'astro:middleware';
import { getSession } from '@/lib/auth';

const protectedPaths = ['/dashboard', '/settings', '/api/user'];

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname } = context.url;

  // Check if path requires auth
  const isProtected = protectedPaths.some(p => pathname.startsWith(p));

  if (isProtected) {
    const sessionId = context.cookies.get('session')?.value;
    const session = sessionId ? getSession(sessionId) : null;

    if (!session) {
      // Redirect to login
      return context.redirect('/login?redirect=' + encodeURIComponent(pathname));
    }

    // Attach user to context for downstream use
    context.locals.userId = session.userId;
  }

  return next();
});
```

### Protected React Components

```tsx
// components/ProtectedContent.tsx
import { useEffect, useState, type ReactNode } from 'react';

interface User {
  id: string;
  name: string;
  email: string;
}

export function ProtectedContent({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/me')
      .then(r => {
        if (r.ok) return r.json();
        throw new Error('Not authenticated');
      })
      .then(setUser)
      .catch(() => {
        window.location.href = '/login';
      })
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!user) {
    return null; // Redirecting
  }

  return <>{children}</>;
}
```

## Input Validation

### Server-Side Validation

```typescript
// src/pages/api/users.ts
import type { APIRoute } from 'astro';
import { z } from 'zod';

const createUserSchema = z.object({
  name: z.string().min(2).max(100),
  email: z.string().email().max(255),
  password: z.string()
    .min(8)
    .regex(/[A-Z]/, 'Must contain uppercase')
    .regex(/[a-z]/, 'Must contain lowercase')
    .regex(/[0-9]/, 'Must contain number'),
  role: z.enum(['user', 'admin']).default('user'),
});

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const data = createUserSchema.parse(body);

    // Data is validated and typed
    // Process creation...

    return new Response(JSON.stringify({ success: true }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({
        error: 'Validation failed',
        issues: error.issues,
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Server error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
```

### Rate Limiting

```typescript
// lib/rate-limit.ts
interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const limits = new Map<string, RateLimitEntry>();

export interface RateLimitConfig {
  windowMs: number; // Time window in ms
  max: number;      // Max requests per window
}

export function rateLimit(
  key: string,
  config: RateLimitConfig = { windowMs: 60000, max: 100 }
): { allowed: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const entry = limits.get(key);

  if (!entry || entry.resetAt < now) {
    // New window
    const resetAt = now + config.windowMs;
    limits.set(key, { count: 1, resetAt });
    return { allowed: true, remaining: config.max - 1, resetAt };
  }

  if (entry.count >= config.max) {
    // Rate limited
    return { allowed: false, remaining: 0, resetAt: entry.resetAt };
  }

  // Increment
  entry.count++;
  return { allowed: true, remaining: config.max - entry.count, resetAt: entry.resetAt };
}

// Middleware usage
export const onRequest = defineMiddleware(async (context, next) => {
  const ip = context.request.headers.get('x-forwarded-for') || 'unknown';
  const { pathname } = context.url;

  // Stricter limits for auth endpoints
  const config = pathname.startsWith('/api/auth')
    ? { windowMs: 60000, max: 5 }  // 5 requests per minute
    : { windowMs: 60000, max: 100 }; // 100 requests per minute

  const { allowed, remaining, resetAt } = rateLimit(`${ip}:${pathname}`, config);

  if (!allowed) {
    return new Response('Too Many Requests', {
      status: 429,
      headers: {
        'Retry-After': String(Math.ceil((resetAt - Date.now()) / 1000)),
        'X-RateLimit-Remaining': '0',
      },
    });
  }

  const response = await next();
  response.headers.set('X-RateLimit-Remaining', String(remaining));

  return response;
});
```

## Secure Cookies

```typescript
// lib/cookies.ts
import type { AstroCookieSetOptions } from 'astro';

export const secureCookieOptions: AstroCookieSetOptions = {
  httpOnly: true,           // Not accessible via JavaScript
  secure: true,             // HTTPS only
  sameSite: 'strict',       // Strict same-site policy
  path: '/',                // Available site-wide
  maxAge: 60 * 60 * 24 * 7, // 7 days
};

// For session cookies
export const sessionCookieOptions: AstroCookieSetOptions = {
  ...secureCookieOptions,
  sameSite: 'lax', // Allow top-level navigation
};

// Usage
cookies.set('session', sessionId, sessionCookieOptions);

// For CSRF tokens
cookies.set('csrf', csrfToken, {
  ...secureCookieOptions,
  sameSite: 'strict',
});
```

## Dependency Security

### Audit Dependencies

```bash
# Check for vulnerabilities
bun audit

# Update all dependencies
bun update

# Check outdated packages
bun outdated
```

### Lockfile Integrity

```bash
# Always commit bun.lockb
# Use frozen lockfile in CI
bun install --frozen-lockfile
```

## Security Checklist

### Development

- [ ] Never log sensitive data (passwords, tokens, PII)
- [ ] Use environment variables for secrets
- [ ] Validate all input server-side
- [ ] Sanitize user HTML before rendering
- [ ] Use parameterized queries (no SQL injection)
- [ ] Implement rate limiting
- [ ] Add CSRF protection to forms

### Deployment

- [ ] Use HTTPS everywhere
- [ ] Set security headers (CSP, HSTS, etc.)
- [ ] Configure secure cookies
- [ ] Enable HTTP/2
- [ ] Review error messages (no stack traces in prod)
- [ ] Audit dependencies regularly
- [ ] Monitor for security alerts

### Authentication

- [ ] Hash passwords (bcrypt/argon2)
- [ ] Implement account lockout
- [ ] Use secure session management
- [ ] Validate redirect URLs
- [ ] Implement proper logout (invalidate sessions)

## Common Vulnerabilities

| Vulnerability | Prevention |
|---------------|------------|
| XSS | Auto-escaping, sanitize user HTML, CSP |
| CSRF | Tokens, SameSite cookies |
| SQL Injection | Parameterized queries, ORMs |
| Auth Bypass | Server-side validation, middleware |
| Sensitive Data Exposure | HTTPS, secure cookies, no logging |
| Rate Limiting | Implement per-IP/user limits |
| Dependency Vulnerabilities | Regular audits, updates |
