# React Reference

## Overview

React powers interactive islands within Astro pages. Use React for complex UI
components, especially when using Shadcn UI. For simple islands where bundle
size matters, consider Preact.

## Component Patterns

### Functional Components with TypeScript

```tsx
// components/Card.tsx
import { type ReactNode } from 'react';

interface CardProps {
  title: string;
  description?: string;
  children: ReactNode;
  variant?: 'default' | 'outlined' | 'elevated';
  className?: string;
}

export function Card({
  title,
  description,
  children,
  variant = 'default',
  className = '',
}: CardProps) {
  const variants = {
    default: 'bg-card border',
    outlined: 'border-2',
    elevated: 'bg-card shadow-lg',
  };

  return (
    <div className={`rounded-lg p-6 ${variants[variant]} ${className}`}>
      <h3 className="text-lg font-semibold">{title}</h3>
      {description && (
        <p className="text-muted-foreground mt-1">{description}</p>
      )}
      <div className="mt-4">{children}</div>
    </div>
  );
}
```

### Custom Hooks

```tsx
// hooks/useLocalStorage.ts
import { useState, useEffect } from 'react';

export function useLocalStorage<T>(
  key: string,
  initialValue: T
): [T, (value: T | ((prev: T) => T)) => void] {
  // Get from localStorage or use initial
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.error(`Error reading localStorage key "${key}":`, error);
      return initialValue;
    }
  });

  // Sync to localStorage
  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      window.localStorage.setItem(key, JSON.stringify(storedValue));
    } catch (error) {
      console.error(`Error setting localStorage key "${key}":`, error);
    }
  }, [key, storedValue]);

  return [storedValue, setStoredValue];
}

// hooks/useDebounce.ts
import { useState, useEffect } from 'react';

export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);

  return debouncedValue;
}

// hooks/useMediaQuery.ts
import { useState, useEffect } from 'react';

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    setMatches(media.matches);

    const listener = (e: MediaQueryListEvent) => setMatches(e.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, [query]);

  return matches;
}
```

### Compound Components Pattern

```tsx
// components/Tabs.tsx
import {
  createContext,
  useContext,
  useState,
  type ReactNode,
} from 'react';

interface TabsContextValue {
  activeTab: string;
  setActiveTab: (id: string) => void;
}

const TabsContext = createContext<TabsContextValue | null>(null);

function useTabs() {
  const context = useContext(TabsContext);
  if (!context) {
    throw new Error('Tabs compound components must be used within <Tabs>');
  }
  return context;
}

interface TabsProps {
  defaultValue: string;
  children: ReactNode;
  className?: string;
}

export function Tabs({ defaultValue, children, className }: TabsProps) {
  const [activeTab, setActiveTab] = useState(defaultValue);

  return (
    <TabsContext.Provider value={{ activeTab, setActiveTab }}>
      <div className={className}>{children}</div>
    </TabsContext.Provider>
  );
}

interface TabsListProps {
  children: ReactNode;
  className?: string;
}

export function TabsList({ children, className }: TabsListProps) {
  return (
    <div
      role="tablist"
      className={`flex gap-1 border-b ${className}`}
    >
      {children}
    </div>
  );
}

interface TabsTriggerProps {
  value: string;
  children: ReactNode;
  className?: string;
}

export function TabsTrigger({ value, children, className }: TabsTriggerProps) {
  const { activeTab, setActiveTab } = useTabs();
  const isActive = activeTab === value;

  return (
    <button
      role="tab"
      aria-selected={isActive}
      onClick={() => setActiveTab(value)}
      className={`
        px-4 py-2 text-sm font-medium transition-colors
        ${isActive
          ? 'border-b-2 border-primary text-primary'
          : 'text-muted-foreground hover:text-foreground'
        }
        ${className}
      `}
    >
      {children}
    </button>
  );
}

interface TabsContentProps {
  value: string;
  children: ReactNode;
  className?: string;
}

export function TabsContent({ value, children, className }: TabsContentProps) {
  const { activeTab } = useTabs();

  if (activeTab !== value) return null;

  return (
    <div
      role="tabpanel"
      className={`mt-4 ${className}`}
    >
      {children}
    </div>
  );
}

// Usage
function Example() {
  return (
    <Tabs defaultValue="overview">
      <TabsList>
        <TabsTrigger value="overview">Overview</TabsTrigger>
        <TabsTrigger value="analytics">Analytics</TabsTrigger>
        <TabsTrigger value="settings">Settings</TabsTrigger>
      </TabsList>
      <TabsContent value="overview">Overview content...</TabsContent>
      <TabsContent value="analytics">Analytics content...</TabsContent>
      <TabsContent value="settings">Settings content...</TabsContent>
    </Tabs>
  );
}
```

## State Management

### State Hierarchy

```tsx
// 1. Local State (useState)
function Counter() {
  const [count, setCount] = useState(0);
  return <button onClick={() => setCount(c => c + 1)}>{count}</button>;
}

// 2. Derived State (compute, don't store)
function FilteredList({ items, searchQuery }: Props) {
  // Good: Derive from props
  const filteredItems = useMemo(
    () => items.filter(item => item.name.includes(searchQuery)),
    [items, searchQuery]
  );

  // Bad: Syncing state with useEffect
  // const [filteredItems, setFilteredItems] = useState(items);
  // useEffect(() => setFilteredItems(...), [items, searchQuery]);

  return <ul>{filteredItems.map(...)}</ul>;
}

// 3. Context for UI State (theme, locale, auth)
const ThemeContext = createContext<'light' | 'dark'>('light');

function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useLocalStorage<'light' | 'dark'>('theme', 'light');

  return (
    <ThemeContext.Provider value={{ theme, setTheme }}>
      {children}
    </ThemeContext.Provider>
  );
}

// 4. Server State (React Query)
function UserProfile({ userId }: { userId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['user', userId],
    queryFn: () => fetchUser(userId),
    staleTime: 5 * 60 * 1000, // 5 minutes
  });

  if (isLoading) return <Skeleton />;
  if (error) return <Error error={error} />;
  return <Profile user={data} />;
}

// 5. Global State (Zustand for complex cases)
import { create } from 'zustand';

interface CartStore {
  items: CartItem[];
  addItem: (item: CartItem) => void;
  removeItem: (id: string) => void;
  total: number;
}

const useCartStore = create<CartStore>((set, get) => ({
  items: [],
  addItem: (item) => set((state) => ({ items: [...state.items, item] })),
  removeItem: (id) => set((state) => ({
    items: state.items.filter(i => i.id !== id)
  })),
  get total() {
    return get().items.reduce((sum, item) => sum + item.price, 0);
  },
}));
```

### React Query Patterns

```tsx
// hooks/api/useProducts.ts
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

// Types
interface Product {
  id: string;
  name: string;
  price: number;
  category: string;
}

interface CreateProductInput {
  name: string;
  price: number;
  category: string;
}

// Query keys factory
const productKeys = {
  all: ['products'] as const,
  lists: () => [...productKeys.all, 'list'] as const,
  list: (filters: string) => [...productKeys.lists(), { filters }] as const,
  details: () => [...productKeys.all, 'detail'] as const,
  detail: (id: string) => [...productKeys.details(), id] as const,
};

// Fetch all products
export function useProducts(category?: string) {
  return useQuery({
    queryKey: productKeys.list(category || 'all'),
    queryFn: async () => {
      const params = category ? `?category=${category}` : '';
      const response = await fetch(`/api/products${params}`);
      if (!response.ok) throw new Error('Failed to fetch products');
      return response.json() as Promise<Product[]>;
    },
    staleTime: 5 * 60 * 1000, // Consider fresh for 5 minutes
    gcTime: 30 * 60 * 1000,   // Keep in cache for 30 minutes
  });
}

// Fetch single product
export function useProduct(id: string) {
  return useQuery({
    queryKey: productKeys.detail(id),
    queryFn: async () => {
      const response = await fetch(`/api/products/${id}`);
      if (!response.ok) throw new Error('Product not found');
      return response.json() as Promise<Product>;
    },
    enabled: !!id, // Only fetch when id is provided
  });
}

// Create product with optimistic update
export function useCreateProduct() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (input: CreateProductInput) => {
      const response = await fetch('/api/products', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      if (!response.ok) throw new Error('Failed to create product');
      return response.json() as Promise<Product>;
    },
    // Optimistic update
    onMutate: async (newProduct) => {
      // Cancel outgoing refetches
      await queryClient.cancelQueries({ queryKey: productKeys.lists() });

      // Snapshot current value
      const previousProducts = queryClient.getQueryData(productKeys.list('all'));

      // Optimistically add to cache
      queryClient.setQueryData(productKeys.list('all'), (old: Product[] = []) => [
        ...old,
        { ...newProduct, id: 'temp-' + Date.now() },
      ]);

      return { previousProducts };
    },
    // Rollback on error
    onError: (err, newProduct, context) => {
      queryClient.setQueryData(
        productKeys.list('all'),
        context?.previousProducts
      );
    },
    // Refetch after success or error
    onSettled: () => {
      queryClient.invalidateQueries({ queryKey: productKeys.lists() });
    },
  });
}

// Delete product
export function useDeleteProduct() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`/api/products/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) throw new Error('Failed to delete product');
    },
    onSuccess: (_, id) => {
      // Remove from cache immediately
      queryClient.setQueryData(productKeys.list('all'), (old: Product[] = []) =>
        old.filter(p => p.id !== id)
      );
      // Invalidate to ensure consistency
      queryClient.invalidateQueries({ queryKey: productKeys.lists() });
    },
  });
}
```

## Error Boundaries

### Class-Based Error Boundary

```tsx
// components/ErrorBoundary.tsx
import { Component, type ReactNode, type ErrorInfo } from 'react';

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  onError?: (error: Error, errorInfo: ErrorInfo) => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log to error reporting service
    console.error('Error caught by boundary:', error, errorInfo);
    this.props.onError?.(error, errorInfo);

    // Send to Sentry, DataDog, etc.
    // Sentry.captureException(error, { extra: errorInfo });
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      return (
        <div className="p-6 bg-destructive/10 rounded-lg text-center">
          <h2 className="text-lg font-semibold text-destructive">
            Something went wrong
          </h2>
          <p className="mt-2 text-muted-foreground">
            {this.state.error?.message || 'An unexpected error occurred'}
          </p>
          <button
            onClick={() => this.setState({ hasError: false, error: null })}
            className="mt-4 px-4 py-2 bg-primary text-primary-foreground rounded"
          >
            Try Again
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
```

### Functional Error Handling with react-error-boundary

```tsx
// components/ErrorFallback.tsx
import { FallbackProps } from 'react-error-boundary';
import { Button } from '@/components/ui/button';

export function ErrorFallback({ error, resetErrorBoundary }: FallbackProps) {
  return (
    <div
      role="alert"
      className="p-6 bg-destructive/10 rounded-lg text-center"
    >
      <h2 className="text-lg font-semibold text-destructive">
        Oops! Something went wrong
      </h2>
      <pre className="mt-2 text-sm text-muted-foreground overflow-auto">
        {error.message}
      </pre>
      <Button onClick={resetErrorBoundary} className="mt-4">
        Try Again
      </Button>
    </div>
  );
}

// Usage
import { ErrorBoundary } from 'react-error-boundary';

function App() {
  return (
    <ErrorBoundary
      FallbackComponent={ErrorFallback}
      onError={(error, info) => {
        // Log to service
        console.error('Error:', error);
        console.error('Component stack:', info.componentStack);
      }}
      onReset={() => {
        // Clear any error-related state
      }}
    >
      <MainContent />
    </ErrorBoundary>
  );
}
```

### Suspense Boundaries for Async

```tsx
// components/AsyncBoundary.tsx
import { Suspense, type ReactNode } from 'react';
import { ErrorBoundary, type FallbackProps } from 'react-error-boundary';

interface AsyncBoundaryProps {
  children: ReactNode;
  loadingFallback?: ReactNode;
  errorFallback?: (props: FallbackProps) => ReactNode;
}

export function AsyncBoundary({
  children,
  loadingFallback = <div className="animate-pulse">Loading...</div>,
  errorFallback = ErrorFallback,
}: AsyncBoundaryProps) {
  return (
    <ErrorBoundary FallbackComponent={errorFallback}>
      <Suspense fallback={loadingFallback}>
        {children}
      </Suspense>
    </ErrorBoundary>
  );
}

// Usage with React Query
function ProductPage({ id }: { id: string }) {
  return (
    <AsyncBoundary
      loadingFallback={<ProductSkeleton />}
      errorFallback={({ error, resetErrorBoundary }) => (
        <ProductError error={error} onRetry={resetErrorBoundary} />
      )}
    >
      <ProductDetails id={id} />
    </AsyncBoundary>
  );
}
```

## Performance Optimization

### Core Web Vitals Focus

```tsx
// Optimize LCP (Largest Contentful Paint)
// - Prioritize above-the-fold content
// - Preload critical images

// pages/index.astro (Astro handles this well)
<head>
  <link rel="preload" as="image" href="/hero.webp" />
</head>

// React component for optimized images
function HeroImage() {
  return (
    <img
      src="/hero.webp"
      alt="Hero"
      // Add dimensions to prevent layout shift (CLS)
      width={1200}
      height={600}
      // Eager load above-fold images
      loading="eager"
      fetchPriority="high"
      decoding="async"
    />
  );
}

// Optimize CLS (Cumulative Layout Shift)
// - Reserve space for dynamic content
function ImageWithPlaceholder({ src, alt, width, height }: Props) {
  return (
    <div
      style={{ aspectRatio: `${width}/${height}` }}
      className="bg-muted"
    >
      <img
        src={src}
        alt={alt}
        width={width}
        height={height}
        loading="lazy"
        className="w-full h-full object-cover"
      />
    </div>
  );
}

// Optimize INP (Interaction to Next Paint)
// - Use transitions for non-urgent updates
import { useTransition, useState } from 'react';

function SearchResults() {
  const [query, setQuery] = useState('');
  const [isPending, startTransition] = useTransition();

  function handleSearch(value: string) {
    // Urgent: Update input immediately
    setQuery(value);

    // Non-urgent: Filter results can be deferred
    startTransition(() => {
      setFilteredResults(filterItems(value));
    });
  }

  return (
    <div>
      <input
        value={query}
        onChange={(e) => handleSearch(e.target.value)}
      />
      {isPending && <span className="text-muted">Filtering...</span>}
      <Results items={filteredResults} />
    </div>
  );
}
```

### Memoization Patterns

```tsx
// React.memo for component memoization
interface ItemProps {
  item: Product;
  onSelect: (id: string) => void;
}

const ProductItem = memo(function ProductItem({ item, onSelect }: ItemProps) {
  return (
    <div onClick={() => onSelect(item.id)}>
      {item.name} - ${item.price}
    </div>
  );
});

// useMemo for expensive calculations
function ExpensiveList({ items, sortBy }: Props) {
  const sortedItems = useMemo(() => {
    console.log('Sorting items...'); // Should only log when deps change
    return [...items].sort((a, b) => {
      if (sortBy === 'price') return a.price - b.price;
      return a.name.localeCompare(b.name);
    });
  }, [items, sortBy]);

  return <ul>{sortedItems.map(...)}</ul>;
}

// useCallback for stable function references
function Parent() {
  const [count, setCount] = useState(0);

  // Without useCallback: new function on every render
  // const handleClick = (id: string) => console.log(id);

  // With useCallback: stable reference
  const handleClick = useCallback((id: string) => {
    console.log(id);
  }, []); // No dependencies, function never changes

  return (
    <>
      <button onClick={() => setCount(c => c + 1)}>
        Count: {count}
      </button>
      {/* ProductItem won't re-render when count changes */}
      <ProductItem item={product} onSelect={handleClick} />
    </>
  );
}
```

### Code Splitting

```tsx
// Lazy load routes/components
import { lazy, Suspense } from 'react';

// Instead of: import { HeavyChart } from './HeavyChart';
const HeavyChart = lazy(() => import('./HeavyChart'));

function Dashboard() {
  return (
    <div>
      <h1>Dashboard</h1>
      <Suspense fallback={<ChartSkeleton />}>
        <HeavyChart data={data} />
      </Suspense>
    </div>
  );
}

// Named exports with lazy
const ProductModal = lazy(() =>
  import('./ProductModal').then(module => ({
    default: module.ProductModal
  }))
);

// Preload on hover
function ProductCard({ product }: Props) {
  const handleMouseEnter = () => {
    // Preload the modal component
    import('./ProductModal');
  };

  return (
    <div onMouseEnter={handleMouseEnter}>
      <button onClick={() => setShowModal(true)}>
        View Details
      </button>
    </div>
  );
}
```

## Testing with MSW

### Setup MSW

```typescript
// mocks/handlers.ts
import { http, HttpResponse } from 'msw';

export const handlers = [
  // GET /api/products
  http.get('/api/products', ({ request }) => {
    const url = new URL(request.url);
    const category = url.searchParams.get('category');

    let products = mockProducts;
    if (category) {
      products = products.filter(p => p.category === category);
    }

    return HttpResponse.json(products);
  }),

  // GET /api/products/:id
  http.get('/api/products/:id', ({ params }) => {
    const product = mockProducts.find(p => p.id === params.id);

    if (!product) {
      return HttpResponse.json(
        { error: 'Product not found' },
        { status: 404 }
      );
    }

    return HttpResponse.json(product);
  }),

  // POST /api/products
  http.post('/api/products', async ({ request }) => {
    const body = await request.json();
    const newProduct = {
      id: crypto.randomUUID(),
      ...body,
    };

    return HttpResponse.json(newProduct, { status: 201 });
  }),

  // Simulate network delay
  http.get('/api/slow', async () => {
    await new Promise(resolve => setTimeout(resolve, 2000));
    return HttpResponse.json({ message: 'Finally!' });
  }),

  // Simulate error
  http.get('/api/error', () => {
    return HttpResponse.json(
      { error: 'Internal Server Error' },
      { status: 500 }
    );
  }),
];

const mockProducts = [
  { id: '1', name: 'Product 1', price: 99, category: 'electronics' },
  { id: '2', name: 'Product 2', price: 149, category: 'clothing' },
];
```

```typescript
// mocks/server.ts
import { setupServer } from 'msw/node';
import { handlers } from './handlers';

export const server = setupServer(...handlers);
```

```typescript
// mocks/browser.ts
import { setupWorker } from 'msw/browser';
import { handlers } from './handlers';

export const worker = setupWorker(...handlers);
```

### Component Tests with MSW

```tsx
// components/__tests__/ProductList.test.tsx
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { http, HttpResponse } from 'msw';
import { server } from '@/mocks/server';
import { ProductList } from '../ProductList';

// Setup
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      {ui}
    </QueryClientProvider>
  );
}

describe('ProductList', () => {
  it('renders products from API', async () => {
    renderWithProviders(<ProductList />);

    // Should show loading state
    expect(screen.getByText(/loading/i)).toBeInTheDocument();

    // Wait for products to load
    await waitFor(() => {
      expect(screen.getByText('Product 1')).toBeInTheDocument();
      expect(screen.getByText('Product 2')).toBeInTheDocument();
    });
  });

  it('handles API errors gracefully', async () => {
    // Override handler for this test
    server.use(
      http.get('/api/products', () => {
        return HttpResponse.json(
          { error: 'Server error' },
          { status: 500 }
        );
      })
    );

    renderWithProviders(<ProductList />);

    await waitFor(() => {
      expect(screen.getByText(/error/i)).toBeInTheDocument();
    });
  });

  it('filters products by category', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ProductList />);

    // Wait for initial load
    await screen.findByText('Product 1');

    // Click category filter
    await user.click(screen.getByRole('button', { name: /electronics/i }));

    // Should only show electronics
    await waitFor(() => {
      expect(screen.getByText('Product 1')).toBeInTheDocument();
      expect(screen.queryByText('Product 2')).not.toBeInTheDocument();
    });
  });

  it('creates new product', async () => {
    const user = userEvent.setup();
    renderWithProviders(<ProductList />);

    // Wait for list to load
    await screen.findByText('Product 1');

    // Open create form
    await user.click(screen.getByRole('button', { name: /add product/i }));

    // Fill form
    await user.type(screen.getByLabelText(/name/i), 'New Product');
    await user.type(screen.getByLabelText(/price/i), '199');

    // Submit
    await user.click(screen.getByRole('button', { name: /save/i }));

    // Should show new product
    await waitFor(() => {
      expect(screen.getByText('New Product')).toBeInTheDocument();
    });
  });
});
```

### Testing Accessibility

```tsx
// components/__tests__/Button.test.tsx
import { render, screen } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import { Button } from '../Button';

expect.extend(toHaveNoViolations);

describe('Button accessibility', () => {
  it('has no accessibility violations', async () => {
    const { container } = render(
      <Button onClick={() => {}}>Click me</Button>
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('has no violations when disabled', async () => {
    const { container } = render(
      <Button disabled>Disabled button</Button>
    );

    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('is focusable and has correct role', () => {
    render(<Button onClick={() => {}}>Click me</Button>);

    const button = screen.getByRole('button', { name: /click me/i });
    expect(button).toBeInTheDocument();
    expect(button).not.toHaveAttribute('tabindex', '-1');
  });
});
```

## Accessibility Patterns

### Focus Management

```tsx
// components/Modal.tsx
import { useRef, useEffect, type ReactNode } from 'react';
import { createPortal } from 'react-dom';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
}

export function Modal({ isOpen, onClose, title, children }: ModalProps) {
  const modalRef = useRef<HTMLDivElement>(null);
  const previousActiveElement = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      // Store current focus
      previousActiveElement.current = document.activeElement as HTMLElement;

      // Focus the modal
      modalRef.current?.focus();

      // Trap focus within modal
      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          onClose();
        }

        if (e.key === 'Tab') {
          const focusable = modalRef.current?.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );

          if (!focusable?.length) return;

          const first = focusable[0] as HTMLElement;
          const last = focusable[focusable.length - 1] as HTMLElement;

          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      };

      document.addEventListener('keydown', handleKeyDown);
      return () => document.removeEventListener('keydown', handleKeyDown);
    } else if (previousActiveElement.current) {
      // Restore focus when closing
      previousActiveElement.current.focus();
    }
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return createPortal(
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal */}
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
        tabIndex={-1}
        className="relative bg-background rounded-lg p-6 max-w-md w-full mx-4 shadow-xl"
      >
        <h2 id="modal-title" className="text-xl font-semibold">
          {title}
        </h2>
        <div className="mt-4">{children}</div>
        <button
          onClick={onClose}
          className="absolute top-4 right-4"
          aria-label="Close modal"
        >
          ✕
        </button>
      </div>
    </div>,
    document.body
  );
}
```

### Skip Link

```tsx
// components/SkipLink.tsx
export function SkipLink() {
  return (
    <a
      href="#main-content"
      className="
        sr-only focus:not-sr-only
        focus:absolute focus:top-4 focus:left-4
        focus:z-50 focus:px-4 focus:py-2
        focus:bg-primary focus:text-primary-foreground
        focus:rounded focus:outline-none
      "
    >
      Skip to main content
    </a>
  );
}

// In layout
function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <SkipLink />
      <Header />
      <main id="main-content" tabIndex={-1}>
        {children}
      </main>
      <Footer />
    </>
  );
}
```

## Common Patterns Summary

| Pattern | Use Case |
|---------|----------|
| `useState` | Local UI state |
| `useReducer` | Complex local state |
| `useMemo` | Expensive calculations |
| `useCallback` | Stable function refs for children |
| `React.memo` | Prevent child re-renders |
| `useTransition` | Non-urgent state updates |
| `useDeferredValue` | Defer expensive renders |
| `lazy` + `Suspense` | Code splitting |
| `ErrorBoundary` | Graceful error handling |
| React Query | Server state management |
| Zustand | Global client state |
