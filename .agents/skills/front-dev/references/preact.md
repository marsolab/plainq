# Preact Reference

## Overview

Preact is a fast 3KB alternative to React with the same modern API. Use it for:

- Bundle-critical islands (saves ~37KB vs React)
- High-frequency updates with Signals
- Web Components output
- Simple widgets that don't need Shadcn UI

## When to Choose Preact vs React

| Scenario | Choose |
|----------|--------|
| Using Shadcn UI | React |
| Bundle size critical (<50KB) | Preact |
| Simple widget (counter, toggle) | Preact |
| High-frequency updates (live data) | Preact + Signals |
| Complex state (React Query, Zustand) | React |
| Web Component output | Preact |
| Need specific React library | Check compat, then decide |

## Setup in Astro

```bash
# Add Preact integration
bunx astro add preact

# If using both React and Preact
bunx astro add react preact
```

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import preact from '@astrojs/preact';
import react from '@astrojs/react';

export default defineConfig({
  integrations: [
    // Order matters: first one is default for .tsx
    react({
      include: ['**/react/*', '**/*.react.tsx'],
    }),
    preact({
      include: ['**/preact/*', '**/*.preact.tsx'],
      compat: true, // Enable preact/compat for React libs
    }),
  ],
});
```

## File Naming Convention

```text
src/components/
├── Counter.tsx           # Default (React in above config)
├── Counter.preact.tsx    # Explicitly Preact
├── Counter.react.tsx     # Explicitly React
├── react/
│   └── DataTable.tsx     # React (by folder)
└── preact/
    └── LivePrice.tsx     # Preact (by folder)
```

## Signals for Fine-Grained Reactivity

### Basic Signals

```tsx
// components/preact/Counter.tsx
import { signal, computed } from '@preact/signals';

// Create signals OUTSIDE component
const count = signal(0);
const doubled = computed(() => count.value * 2);

export default function Counter() {
  return (
    <div className="flex items-center gap-4">
      <button onClick={() => count.value--}>-</button>
      <span>{count}</span>
      <button onClick={() => count.value++}>+</button>
      <span className="text-muted-foreground">
        (doubled: {doubled})
      </span>
    </div>
  );
}
```

### Signals Store Pattern

```tsx
// stores/cart.ts
import { signal, computed, effect } from '@preact/signals';

// Cart item type
interface CartItem {
  id: string;
  name: string;
  price: number;
  quantity: number;
}

// Create signals
const items = signal<CartItem[]>([]);
const discount = signal(0);

// Computed values
const subtotal = computed(() =>
  items.value.reduce((sum, item) => sum + item.price * item.quantity, 0)
);

const total = computed(() =>
  subtotal.value * (1 - discount.value / 100)
);

const itemCount = computed(() =>
  items.value.reduce((sum, item) => sum + item.quantity, 0)
);

// Actions
function addItem(item: Omit<CartItem, 'quantity'>) {
  const existing = items.value.find(i => i.id === item.id);
  if (existing) {
    items.value = items.value.map(i =>
      i.id === item.id ? { ...i, quantity: i.quantity + 1 } : i
    );
  } else {
    items.value = [...items.value, { ...item, quantity: 1 }];
  }
}

function removeItem(id: string) {
  items.value = items.value.filter(i => i.id !== id);
}

function updateQuantity(id: string, quantity: number) {
  if (quantity <= 0) {
    removeItem(id);
  } else {
    items.value = items.value.map(i =>
      i.id === id ? { ...i, quantity } : i
    );
  }
}

function clearCart() {
  items.value = [];
  discount.value = 0;
}

function applyDiscount(percent: number) {
  discount.value = Math.min(100, Math.max(0, percent));
}

// Persist to localStorage
effect(() => {
  localStorage.setItem('cart', JSON.stringify(items.value));
});

// Export store
export const cartStore = {
  // State (read-only access via computed)
  items: computed(() => items.value),
  subtotal,
  total,
  discount: computed(() => discount.value),
  itemCount,
  // Actions
  addItem,
  removeItem,
  updateQuantity,
  clearCart,
  applyDiscount,
};
```

### Using Signals Store in Components

```tsx
// components/preact/CartWidget.tsx
import { cartStore } from '@/stores/cart';

export default function CartWidget() {
  return (
    <div className="relative">
      <button className="p-2">
        🛒
        {cartStore.itemCount.value > 0 && (
          <span className="absolute -top-1 -right-1 bg-primary text-primary-foreground text-xs rounded-full w-5 h-5 flex items-center justify-center">
            {cartStore.itemCount}
          </span>
        )}
      </button>
    </div>
  );
}

// components/preact/CartSummary.tsx
import { cartStore } from '@/stores/cart';

export default function CartSummary() {
  return (
    <div className="p-4 border rounded-lg">
      <h3 className="font-semibold mb-4">Cart Summary</h3>

      {cartStore.items.value.length === 0 ? (
        <p className="text-muted-foreground">Your cart is empty</p>
      ) : (
        <>
          <ul className="space-y-2">
            {cartStore.items.value.map(item => (
              <li key={item.id} className="flex justify-between">
                <span>
                  {item.name} × {item.quantity}
                </span>
                <span>${(item.price * item.quantity).toFixed(2)}</span>
                <button
                  onClick={() => cartStore.removeItem(item.id)}
                  className="text-destructive"
                >
                  ✕
                </button>
              </li>
            ))}
          </ul>

          <div className="border-t mt-4 pt-4">
            <div className="flex justify-between">
              <span>Subtotal:</span>
              <span>${cartStore.subtotal.value.toFixed(2)}</span>
            </div>
            {cartStore.discount.value > 0 && (
              <div className="flex justify-between text-green-600">
                <span>Discount ({cartStore.discount}%):</span>
                <span>-${((cartStore.subtotal.value * cartStore.discount.value) / 100).toFixed(2)}</span>
              </div>
            )}
            <div className="flex justify-between font-bold mt-2">
              <span>Total:</span>
              <span>${cartStore.total.value.toFixed(2)}</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
```

### Real-Time Updates with Signals

```tsx
// components/preact/LivePrice.tsx
import { signal, computed, effect } from '@preact/signals';

const price = signal<number | null>(null);
const previousPrice = signal<number | null>(null);
const lastUpdate = signal<Date | null>(null);
const status = signal<'connecting' | 'connected' | 'error'>('connecting');

// Connect to WebSocket for live prices
function connectToFeed(symbol: string) {
  const ws = new WebSocket(`wss://api.example.com/prices/${symbol}`);

  ws.onopen = () => {
    status.value = 'connected';
  };

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    previousPrice.value = price.value;
    price.value = data.price;
    lastUpdate.value = new Date();
  };

  ws.onerror = () => {
    status.value = 'error';
  };

  return () => ws.close();
}

// Computed price change
const priceChange = computed(() => {
  if (price.value === null || previousPrice.value === null) return null;
  return price.value - previousPrice.value;
});

const priceChangePercent = computed(() => {
  if (priceChange.value === null || previousPrice.value === null) return null;
  return (priceChange.value / previousPrice.value) * 100;
});

export default function LivePrice({ symbol = 'BTC-USD' }) {
  // Connect on mount
  import { useEffect } from 'preact/hooks';

  useEffect(() => {
    return connectToFeed(symbol);
  }, [symbol]);

  return (
    <div className="p-4 rounded-lg border bg-card">
      <div className="flex items-center justify-between mb-2">
        <h3 className="font-semibold">{symbol}</h3>
        <span className={`text-xs px-2 py-1 rounded ${
          status.value === 'connected'
            ? 'bg-green-100 text-green-800'
            : status.value === 'error'
            ? 'bg-red-100 text-red-800'
            : 'bg-yellow-100 text-yellow-800'
        }`}>
          {status}
        </span>
      </div>

      {price.value !== null ? (
        <>
          <div className="text-3xl font-mono font-bold">
            ${price.value.toFixed(2)}
          </div>

          {priceChange.value !== null && (
            <div className={`text-sm ${
              priceChange.value >= 0 ? 'text-green-600' : 'text-red-600'
            }`}>
              {priceChange.value >= 0 ? '▲' : '▼'}
              ${Math.abs(priceChange.value).toFixed(2)}
              ({priceChangePercent.value?.toFixed(2)}%)
            </div>
          )}

          {lastUpdate.value && (
            <div className="text-xs text-muted-foreground mt-2">
              Updated: {lastUpdate.value.toLocaleTimeString()}
            </div>
          )}
        </>
      ) : (
        <div className="animate-pulse">Loading...</div>
      )}
    </div>
  );
}
```

## Web Components Integration

### Create Preact Web Component

```tsx
// components/web/price-ticker.tsx
import register from 'preact-custom-element';
import { signal, computed } from '@preact/signals';

const price = signal(100);
const change = signal(0);

interface PriceTickerProps {
  symbol?: string;
  initialPrice?: number;
}

function PriceTicker({ symbol = 'STOCK', initialPrice = 100 }: PriceTickerProps) {
  // Initialize if provided
  if (initialPrice && price.value === 100) {
    price.value = initialPrice;
  }

  const trend = computed(() => change.value >= 0 ? 'up' : 'down');

  return (
    <div className="inline-flex items-center gap-2 px-3 py-1 rounded bg-card border">
      <span className="font-mono text-sm">{symbol}</span>
      <span className="font-mono font-bold">${price}</span>
      <span className={`text-xs ${
        trend.value === 'up' ? 'text-green-600' : 'text-red-600'
      }`}>
        {trend.value === 'up' ? '▲' : '▼'}{Math.abs(change.value).toFixed(2)}%
      </span>
    </div>
  );
}

// Register as custom element
register(PriceTicker, 'price-ticker', ['symbol', 'initial-price'], {
  shadow: false, // Use light DOM for easier styling
});

// Export for Preact usage too
export default PriceTicker;

// Also export update function for external control
export function updatePrice(newPrice: number) {
  const oldPrice = price.value;
  price.value = newPrice;
  change.value = ((newPrice - oldPrice) / oldPrice) * 100;
}
```

### Build Web Component

```typescript
// build-web-components.ts
await Bun.build({
  entrypoints: ['./src/components/web/price-ticker.tsx'],
  outdir: './dist/web-components',
  target: 'browser',
  minify: true,
  // Include Preact runtime
  external: [], // Bundle everything
});
```

### Use Web Component

```html
<!-- In any HTML page, not just Astro -->
<!DOCTYPE html>
<html>
<head>
  <script type="module" src="/web-components/price-ticker.js"></script>
</head>
<body>
  <!-- Use the custom element -->
  <price-ticker symbol="AAPL" initial-price="178.50"></price-ticker>

  <!-- Multiple instances -->
  <price-ticker symbol="GOOGL" initial-price="141.20"></price-ticker>
  <price-ticker symbol="MSFT" initial-price="378.90"></price-ticker>

  <!-- Update from external JavaScript -->
  <script type="module">
    import { updatePrice } from '/web-components/price-ticker.js';

    // Simulate price updates
    setInterval(() => {
      const change = (Math.random() - 0.5) * 2;
      updatePrice(178.50 + change);
    }, 1000);
  </script>
</body>
</html>
```

## React to Preact Migration

### Step 1: Add preact/compat Alias

```javascript
// vite.config.ts (for standalone Preact projects)
import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

export default defineConfig({
  plugins: [preact()],
  resolve: {
    alias: {
      'react': 'preact/compat',
      'react-dom': 'preact/compat',
      'react-dom/test-utils': 'preact/test-utils',
      'react/jsx-runtime': 'preact/jsx-runtime',
    },
  },
});
```

### Step 2: Verify Compatibility

```tsx
// Test your components still work
import { render, screen } from '@testing-library/preact';
import { MyComponent } from './MyComponent';

test('component renders with preact/compat', () => {
  render(<MyComponent />);
  expect(screen.getByText('Expected Text')).toBeInTheDocument();
});
```

### Step 3: Replace React-Specific Code

```tsx
// Before: React-specific
import { createPortal } from 'react-dom';
import { useId, useSyncExternalStore } from 'react';

// After: Preact equivalents
import { createPortal } from 'preact/compat';
// useId works via compat
// useSyncExternalStore works via compat
```

### Step 4: Adopt Signals (Optional but Recommended)

```tsx
// Before: React hooks
function Counter() {
  const [count, setCount] = useState(0);
  const doubled = useMemo(() => count * 2, [count]);

  return (
    <div>
      <span>{count}</span>
      <span>{doubled}</span>
      <button onClick={() => setCount(c => c + 1)}>+</button>
    </div>
  );
}

// After: Preact signals
import { signal, computed } from '@preact/signals';

const count = signal(0);
const doubled = computed(() => count.value * 2);

function Counter() {
  return (
    <div>
      <span>{count}</span>
      <span>{doubled}</span>
      <button onClick={() => count.value++}>+</button>
    </div>
  );
}
```

### Step 5: Remove preact/compat (Fully Native)

```javascript
// Final: No compat needed
export default defineConfig({
  plugins: [preact()],
  // Remove aliases
});
```

## preact/compat Edge Cases

### Known Differences

| Feature | React | Preact/compat | Solution |
|---------|-------|---------------|----------|
| Synthetic Events | Full polyfill | Partial | Use native events |
| `defaultValue` | Works on all inputs | Limited | Use `value` + onChange |
| Event pooling | Removed in React 17 | Never had | N/A |
| StrictMode | Full | Partial | May not catch all issues |
| `useInsertionEffect` | Supported | Not supported | Use `useLayoutEffect` |
| Server Components | Supported | Not supported | Use Astro SSR instead |

### Event Handling Differences

```tsx
// React: onChange fires on every keystroke for inputs
<input onChange={(e) => setValue(e.target.value)} />

// Preact: onChange fires on blur for some inputs
// Use onInput for consistent behavior
<input onInput={(e) => setValue(e.currentTarget.value)} />
```

### Ref Handling

```tsx
// React: createRef returns { current: null }
const ref = createRef();

// Preact: Works the same with compat
// But for function refs, use useRef
import { useRef } from 'preact/hooks';

function Component() {
  const inputRef = useRef<HTMLInputElement>(null);

  return <input ref={inputRef} />;
}
```

### Libraries That Work with preact/compat

✅ **Usually Work:**

- react-query / @tanstack/react-query
- react-hook-form
- zustand
- framer-motion
- react-router
- react-spring
- @dnd-kit

⚠️ **May Need Adjustments:**

- react-select (use Preact-specific version)
- react-beautiful-dnd (consider @dnd-kit)
- Material UI (heavy, consider alternatives)

❌ **Don't Work / Not Recommended:**

- React Server Components
- React Native (different platform)
- Libraries using React internals

## Testing Preact Components

### Setup Testing Library

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';
import preact from '@preact/preset-vite';

export default defineConfig({
  plugins: [preact()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
  },
});
```

```typescript
// tests/setup.ts
import '@testing-library/jest-dom/vitest';
```

### Component Tests

```tsx
// components/__tests__/Counter.test.tsx
import { render, screen, fireEvent } from '@testing-library/preact';
import Counter from '../Counter';

describe('Counter', () => {
  it('renders initial count', () => {
    render(<Counter />);
    expect(screen.getByText('0')).toBeInTheDocument();
  });

  it('increments on click', async () => {
    render(<Counter />);

    const button = screen.getByRole('button', { name: /increment/i });
    fireEvent.click(button);

    expect(screen.getByText('1')).toBeInTheDocument();
  });
});
```

### Testing Signals

```tsx
// stores/__tests__/cart.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { cartStore } from '../cart';

describe('Cart Store', () => {
  beforeEach(() => {
    cartStore.clearCart();
  });

  it('adds item to cart', () => {
    cartStore.addItem({ id: '1', name: 'Test', price: 10 });

    expect(cartStore.items.value).toHaveLength(1);
    expect(cartStore.items.value[0].name).toBe('Test');
  });

  it('calculates total correctly', () => {
    cartStore.addItem({ id: '1', name: 'Item 1', price: 10 });
    cartStore.addItem({ id: '2', name: 'Item 2', price: 20 });

    expect(cartStore.subtotal.value).toBe(30);
  });

  it('applies discount', () => {
    cartStore.addItem({ id: '1', name: 'Item', price: 100 });
    cartStore.applyDiscount(10);

    expect(cartStore.total.value).toBe(90);
  });
});
```

## Performance Comparison

### Bundle Size

| Library | Size (gzipped) |
|---------|---------------|
| React + ReactDOM | ~40KB |
| Preact | ~3KB |
| Preact + Signals | ~4KB |
| Preact + compat | ~5KB |

### Runtime Performance

Signals provide fine-grained updates:

```tsx
// React: Parent re-renders, children re-render
function Parent() {
  const [count, setCount] = useState(0);

  return (
    <div>
      <ExpensiveChild /> {/* Re-renders on count change */}
      <span>{count}</span>
    </div>
  );
}

// Preact Signals: Only the span updates
const count = signal(0);

function Parent() {
  return (
    <div>
      <ExpensiveChild /> {/* Never re-renders for count */}
      <span>{count}</span> {/* Only this updates */}
    </div>
  );
}
```

## Best Practices

1. **Signals outside components** — Define signals at module level
1. **Use .value sparingly** — Let JSX auto-subscribe
1. **Computed for derived state** — Don't duplicate in signals
1. **Test with preact/compat** — Before removing compat
1. **Check library compatibility** — Before adopting Preact
1. **Use onInput for text inputs** — More consistent than onChange
1. **Profile before optimizing** — Signals aren't always needed
