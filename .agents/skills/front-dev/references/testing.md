# Testing Reference

## Overview

Testing strategy for Astro + React/Preact applications with Bun, Vitest, Testing
Library, and Playwright.

## Testing Pyramid

```text
         /\
        /E2E\        Few, critical paths only
       /------\
      /Component\    User interactions, integration
     /------------\
    /    Unit      \  Many, fast, isolated
   /________________\
```

| Layer | Tools | Purpose | Speed | Count |
|-------|-------|---------|-------|-------|
| Unit | Bun test / Vitest | Pure functions, utilities | Fast | Many |
| Component | Testing Library | React/Preact components | Medium | Some |
| Integration | Testing Library + MSW | Full features with mocks | Medium | Some |
| E2E | Playwright | Critical user flows | Slow | Few |

## Project Setup

### Install Dependencies

```bash
# Testing libraries
bun add -d vitest @testing-library/react @testing-library/user-event
bun add -d @testing-library/jest-dom jsdom

# For Preact
bun add -d @testing-library/preact

# MSW for API mocking
bun add -d msw

# Playwright for E2E
bun add -d @playwright/test

# Accessibility testing
bun add -d jest-axe @axe-core/playwright
```

### Vitest Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
    include: ['src/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['node_modules', 'dist', 'e2e'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      exclude: [
        'node_modules/',
        'tests/',
        '**/*.d.ts',
        '**/*.config.*',
      ],
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
    },
  },
});
```

### Test Setup File

```typescript
// tests/setup.ts
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeAll, afterAll } from 'vitest';
import { server } from './mocks/server';

// Cleanup after each test
afterEach(() => {
  cleanup();
});

// MSW setup
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});

// Mock IntersectionObserver
class MockIntersectionObserver {
  observe = () => {};
  disconnect = () => {};
  unobserve = () => {};
}
window.IntersectionObserver = MockIntersectionObserver as any;

// Mock ResizeObserver
class MockResizeObserver {
  observe = () => {};
  disconnect = () => {};
  unobserve = () => {};
}
window.ResizeObserver = MockResizeObserver as any;
```

## Unit Testing

### Testing Utilities

```typescript
// lib/utils.test.ts
import { describe, it, expect } from 'vitest';
import { cn, formatCurrency, slugify, truncate } from './utils';

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar');
  });

  it('handles conditional classes', () => {
    expect(cn('base', false && 'hidden', true && 'visible')).toBe('base visible');
  });

  it('resolves Tailwind conflicts', () => {
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500');
  });
});

describe('formatCurrency', () => {
  it('formats USD correctly', () => {
    expect(formatCurrency(1234.56)).toBe('$1,234.56');
  });

  it('handles zero', () => {
    expect(formatCurrency(0)).toBe('$0.00');
  });

  it('handles negative values', () => {
    expect(formatCurrency(-99.99)).toBe('-$99.99');
  });
});

describe('slugify', () => {
  it('converts to lowercase', () => {
    expect(slugify('Hello World')).toBe('hello-world');
  });

  it('removes special characters', () => {
    expect(slugify('Hello, World!')).toBe('hello-world');
  });

  it('handles multiple spaces', () => {
    expect(slugify('hello   world')).toBe('hello-world');
  });
});

describe('truncate', () => {
  it('truncates long strings', () => {
    expect(truncate('Hello World', 5)).toBe('Hello...');
  });

  it('returns short strings unchanged', () => {
    expect(truncate('Hi', 5)).toBe('Hi');
  });
});
```

### Testing Custom Hooks

```typescript
// hooks/useLocalStorage.test.ts
import { renderHook, act } from '@testing-library/react';
import { describe, it, expect, beforeEach } from 'vitest';
import { useLocalStorage } from './useLocalStorage';

describe('useLocalStorage', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('returns initial value when localStorage is empty', () => {
    const { result } = renderHook(() => useLocalStorage('key', 'initial'));
    expect(result.current[0]).toBe('initial');
  });

  it('returns stored value from localStorage', () => {
    localStorage.setItem('key', JSON.stringify('stored'));
    const { result } = renderHook(() => useLocalStorage('key', 'initial'));
    expect(result.current[0]).toBe('stored');
  });

  it('updates localStorage when value changes', () => {
    const { result } = renderHook(() => useLocalStorage('key', 'initial'));

    act(() => {
      result.current[1]('updated');
    });

    expect(result.current[0]).toBe('updated');
    expect(JSON.parse(localStorage.getItem('key')!)).toBe('updated');
  });

  it('handles function updates', () => {
    const { result } = renderHook(() => useLocalStorage('count', 0));

    act(() => {
      result.current[1]((prev) => prev + 1);
    });

    expect(result.current[0]).toBe(1);
  });

  it('handles objects', () => {
    const { result } = renderHook(() => useLocalStorage('user', { name: 'John' }));

    act(() => {
      result.current[1]({ name: 'Jane' });
    });

    expect(result.current[0]).toEqual({ name: 'Jane' });
  });
});
```

### Testing with Bun's Test Runner

```typescript
// lib/validation.test.ts
import { describe, test, expect } from 'bun:test';
import { validateEmail, validatePassword, validateForm } from './validation';

describe('validateEmail', () => {
  test('accepts valid emails', () => {
    expect(validateEmail('user@example.com')).toBe(true);
    expect(validateEmail('user+tag@example.co.uk')).toBe(true);
  });

  test('rejects invalid emails', () => {
    expect(validateEmail('invalid')).toBe(false);
    expect(validateEmail('user@')).toBe(false);
    expect(validateEmail('@example.com')).toBe(false);
  });
});

describe('validatePassword', () => {
  test('requires minimum length', () => {
    expect(validatePassword('short')).toContain('at least 8 characters');
  });

  test('requires uppercase', () => {
    expect(validatePassword('lowercase123')).toContain('uppercase');
  });

  test('requires number', () => {
    expect(validatePassword('NoNumbers')).toContain('number');
  });

  test('accepts valid passwords', () => {
    expect(validatePassword('ValidPass123')).toEqual([]);
  });
});
```

## Component Testing

### Basic Component Test

```tsx
// components/Button.test.tsx
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { Button } from './ui/button';

describe('Button', () => {
  it('renders with text', () => {
    render(<Button>Click me</Button>);
    expect(screen.getByRole('button', { name: /click me/i })).toBeInTheDocument();
  });

  it('calls onClick handler', async () => {
    const user = userEvent.setup();
    const handleClick = vi.fn();

    render(<Button onClick={handleClick}>Click me</Button>);
    await user.click(screen.getByRole('button'));

    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('prevents click when disabled', async () => {
    const user = userEvent.setup();
    const handleClick = vi.fn();

    render(<Button onClick={handleClick} disabled>Click me</Button>);
    await user.click(screen.getByRole('button'));

    expect(handleClick).not.toHaveBeenCalled();
  });

  it('applies variant classes', () => {
    render(<Button variant="destructive">Delete</Button>);
    expect(screen.getByRole('button')).toHaveClass('bg-destructive');
  });

  it('supports asChild pattern', () => {
    render(
      <Button asChild>
        <a href="/link">Link Button</a>
      </Button>
    );
    expect(screen.getByRole('link', { name: /link button/i })).toBeInTheDocument();
  });
});
```

### Testing Forms

```tsx
// components/ContactForm.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import ContactForm from './ContactForm';

// Mock fetch
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('ContactForm', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  it('renders all fields', () => {
    render(<ContactForm />);

    expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/message/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument();
  });

  it('shows validation errors for empty submission', async () => {
    const user = userEvent.setup();
    render(<ContactForm />);

    await user.click(screen.getByRole('button', { name: /send/i }));

    await waitFor(() => {
      expect(screen.getByText(/name must be at least/i)).toBeInTheDocument();
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
    });
  });

  it('shows error for invalid email', async () => {
    const user = userEvent.setup();
    render(<ContactForm />);

    await user.type(screen.getByLabelText(/email/i), 'invalid-email');
    await user.click(screen.getByRole('button', { name: /send/i }));

    await waitFor(() => {
      expect(screen.getByText(/please enter a valid email/i)).toBeInTheDocument();
    });
  });

  it('submits form with valid data', async () => {
    const user = userEvent.setup();
    mockFetch.mockResolvedValueOnce({ ok: true, json: () => Promise.resolve({}) });

    render(<ContactForm />);

    await user.type(screen.getByLabelText(/name/i), 'John Doe');
    await user.type(screen.getByLabelText(/email/i), 'john@example.com');
    await user.type(screen.getByLabelText(/message/i), 'Hello, this is a test message!');
    await user.click(screen.getByRole('button', { name: /send/i }));

    await waitFor(() => {
      expect(mockFetch).toHaveBeenCalledWith('/api/contact', expect.objectContaining({
        method: 'POST',
        body: expect.stringContaining('john@example.com'),
      }));
    });
  });

  it('shows loading state during submission', async () => {
    const user = userEvent.setup();
    mockFetch.mockImplementation(() => new Promise(() => {})); // Never resolves

    render(<ContactForm />);

    await user.type(screen.getByLabelText(/name/i), 'John Doe');
    await user.type(screen.getByLabelText(/email/i), 'john@example.com');
    await user.type(screen.getByLabelText(/message/i), 'Hello, test message here!');
    await user.click(screen.getByRole('button', { name: /send/i }));

    expect(await screen.findByText(/sending/i)).toBeInTheDocument();
    expect(screen.getByRole('button')).toBeDisabled();
  });
});
```

### Testing with MSW

```typescript
// tests/mocks/handlers.ts
import { http, HttpResponse } from 'msw';

export const handlers = [
  // GET products
  http.get('/api/products', () => {
    return HttpResponse.json([
      { id: '1', name: 'Product 1', price: 99 },
      { id: '2', name: 'Product 2', price: 149 },
    ]);
  }),

  // GET single product
  http.get('/api/products/:id', ({ params }) => {
    const { id } = params;
    if (id === 'not-found') {
      return HttpResponse.json({ error: 'Not found' }, { status: 404 });
    }
    return HttpResponse.json({ id, name: `Product ${id}`, price: 99 });
  }),

  // POST product
  http.post('/api/products', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json(
      { id: crypto.randomUUID(), ...body },
      { status: 201 }
    );
  }),

  // POST contact
  http.post('/api/contact', async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({ success: true, id: crypto.randomUUID() });
  }),
];
```

```typescript
// tests/mocks/server.ts
import { setupServer } from 'msw/node';
import { handlers } from './handlers';

export const server = setupServer(...handlers);
```

```tsx
// components/ProductList.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/tests/mocks/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ProductList from './ProductList';

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
  );
}

describe('ProductList', () => {
  it('renders products from API', async () => {
    renderWithProviders(<ProductList />);

    await waitFor(() => {
      expect(screen.getByText('Product 1')).toBeInTheDocument();
      expect(screen.getByText('Product 2')).toBeInTheDocument();
    });
  });

  it('shows loading state', () => {
    renderWithProviders(<ProductList />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });

  it('handles API errors', async () => {
    server.use(
      http.get('/api/products', () => {
        return HttpResponse.json({ error: 'Server error' }, { status: 500 });
      })
    );

    renderWithProviders(<ProductList />);

    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument();
    });
  });

  it('handles empty response', async () => {
    server.use(
      http.get('/api/products', () => {
        return HttpResponse.json([]);
      })
    );

    renderWithProviders(<ProductList />);

    await waitFor(() => {
      expect(screen.getByText(/no products/i)).toBeInTheDocument();
    });
  });
});
```

## Accessibility Testing

### Jest-axe Integration

```tsx
// components/Card.test.tsx
import { render } from '@testing-library/react';
import { describe, it, expect } from 'vitest';
import { axe, toHaveNoViolations } from 'jest-axe';
import { Card, CardHeader, CardTitle, CardContent } from './ui/card';

expect.extend(toHaveNoViolations);

describe('Card accessibility', () => {
  it('has no accessibility violations', async () => {
    const { container } = render(
      <Card>
        <CardHeader>
          <CardTitle>Card Title</CardTitle>
        </CardHeader>
        <CardContent>
          <p>Card content goes here.</p>
        </CardContent>
      </Card>
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('has no violations with interactive content', async () => {
    const { container } = render(
      <Card>
        <CardHeader>
          <CardTitle>Form Card</CardTitle>
        </CardHeader>
        <CardContent>
          <form>
            <label htmlFor="email">Email</label>
            <input id="email" type="email" />
            <button type="submit">Submit</button>
          </form>
        </CardContent>
      </Card>
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });
});
```

### Accessibility Queries

```tsx
// Use accessibility queries for better tests
import { render, screen } from '@testing-library/react';

describe('Navigation', () => {
  it('has accessible navigation', () => {
    render(<Navigation />);

    // Prefer accessible queries
    const nav = screen.getByRole('navigation');
    const links = screen.getAllByRole('link');
    const homeLink = screen.getByRole('link', { name: /home/i });

    // Check for proper labels
    expect(nav).toHaveAccessibleName(); // or specific name
    expect(homeLink).toHaveAccessibleName('Home');
  });

  it('supports keyboard navigation', async () => {
    const user = userEvent.setup();
    render(<Navigation />);

    // Tab through navigation
    await user.tab();
    expect(screen.getByRole('link', { name: /home/i })).toHaveFocus();

    await user.tab();
    expect(screen.getByRole('link', { name: /about/i })).toHaveFocus();
  });
});
```

## E2E Testing with Playwright

### Configuration

```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html'],
    ['json', { outputFile: 'test-results/results.json' }],
  ],
  use: {
    baseURL: 'http://localhost:4321',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 13'] },
    },
  ],
  webServer: {
    command: 'bun run preview',
    url: 'http://localhost:4321',
    reuseExistingServer: !process.env.CI,
  },
});
```

### E2E Test Examples

```typescript
// e2e/home.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Homepage', () => {
  test('has correct title', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveTitle(/My Site/);
  });

  test('navigation works', async ({ page }) => {
    await page.goto('/');

    await page.getByRole('link', { name: /about/i }).click();
    await expect(page).toHaveURL('/about');

    await page.getByRole('link', { name: /blog/i }).click();
    await expect(page).toHaveURL('/blog');
  });

  test('hero section is visible', async ({ page }) => {
    await page.goto('/');

    const hero = page.getByTestId('hero');
    await expect(hero).toBeVisible();
    await expect(hero.getByRole('heading', { level: 1 })).toBeVisible();
  });
});
```

### Testing User Flows

```typescript
// e2e/checkout.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Checkout Flow', () => {
  test('complete purchase flow', async ({ page }) => {
    // Start on products page
    await page.goto('/products');

    // Add product to cart
    await page.getByTestId('product-card').first().click();
    await page.getByRole('button', { name: /add to cart/i }).click();

    // Verify cart updated
    const cartCount = page.getByTestId('cart-count');
    await expect(cartCount).toHaveText('1');

    // Go to cart
    await page.getByRole('link', { name: /cart/i }).click();
    await expect(page).toHaveURL('/cart');

    // Proceed to checkout
    await page.getByRole('button', { name: /checkout/i }).click();
    await expect(page).toHaveURL('/checkout');

    // Fill checkout form
    await page.getByLabel(/email/i).fill('test@example.com');
    await page.getByLabel(/name/i).fill('Test User');
    await page.getByLabel(/address/i).fill('123 Test St');
    await page.getByLabel(/city/i).fill('Test City');
    await page.getByLabel(/zip/i).fill('12345');

    // Submit order
    await page.getByRole('button', { name: /place order/i }).click();

    // Verify success
    await expect(page).toHaveURL(/\/order\/confirmation/);
    await expect(page.getByText(/thank you/i)).toBeVisible();
  });

  test('shows validation errors', async ({ page }) => {
    await page.goto('/checkout');

    // Submit without filling form
    await page.getByRole('button', { name: /place order/i }).click();

    // Check for error messages
    await expect(page.getByText(/email is required/i)).toBeVisible();
    await expect(page.getByText(/name is required/i)).toBeVisible();
  });
});
```

### Accessibility E2E Tests

```typescript
// e2e/accessibility.spec.ts
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Accessibility', () => {
  test('homepage has no accessibility violations', async ({ page }) => {
    await page.goto('/');

    const results = await new AxeBuilder({ page }).analyze();
    expect(results.violations).toEqual([]);
  });

  test('form page has no accessibility violations', async ({ page }) => {
    await page.goto('/contact');

    const results = await new AxeBuilder({ page })
      .exclude('.third-party-widget') // Exclude elements you don't control
      .analyze();

    expect(results.violations).toEqual([]);
  });

  test('keyboard navigation works', async ({ page }) => {
    await page.goto('/');

    // Tab to first interactive element
    await page.keyboard.press('Tab');

    // Should focus skip link
    const skipLink = page.getByRole('link', { name: /skip to main/i });
    await expect(skipLink).toBeFocused();

    // Continue tabbing through navigation
    await page.keyboard.press('Tab');
    await expect(page.getByRole('link', { name: /home/i })).toBeFocused();
  });
});
```

## Running Tests

```bash
# Unit and component tests
bun run test              # Run once
bun run test:watch        # Watch mode
bun run test:coverage     # With coverage

# Using Bun's test runner
bun test                  # Run all tests
bun test --watch          # Watch mode
bun test --coverage       # With coverage

# E2E tests
bunx playwright test              # Run all
bunx playwright test --ui         # Interactive UI
bunx playwright test --headed     # See browser
bunx playwright test --debug      # Debug mode

# Specific test file
bun test src/components/Button.test.tsx
bunx playwright test e2e/home.spec.ts
```

## CI Integration

```yaml
# .github/workflows/test.yml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - run: bun install
      - run: bun run test:coverage
      - uses: codecov/codecov-action@v4

  e2e-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v1
      - run: bun install
      - run: bun run build
      - run: bunx playwright install --with-deps
      - run: bunx playwright test
      - uses: actions/upload-artifact@v4
        if: failure()
        with:
          name: playwright-report
          path: playwright-report/
```

## Best Practices

1. **Test behavior, not implementation** — Focus on what users see
1. **Use accessible queries** — `getByRole`, `getByLabelText` over `getByTestId`
1. **Avoid testing implementation details** — Don't test state directly
1. **Keep tests isolated** — Each test should be independent
1. **Mock at the network level** — Use MSW, not module mocks
1. **Test critical paths E2E** — Login, checkout, key features
1. **Run tests in CI** — Catch regressions early
