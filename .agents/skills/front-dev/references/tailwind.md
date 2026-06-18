# Tailwind CSS v4 Reference

## Overview

Tailwind CSS v4 is a utility-first CSS framework with CSS-first configuration.
It integrates seamlessly with Astro and provides the styling foundation for all
components.

## Setup in Astro

```bash
# Add Tailwind integration
bunx astro add tailwind
```

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';

export default defineConfig({
  integrations: [
    tailwind({
      // Use your own globals.css instead of base styles
      applyBaseStyles: false,
    }),
  ],
});
```

## CSS-First Configuration (v4)

### Design Tokens with @theme

```css
/* src/styles/globals.css */
@import "tailwindcss";

@theme {
  /* Colors - using oklch for better color manipulation */
  --color-background: oklch(1 0 0);
  --color-foreground: oklch(0.1 0 0);

  --color-primary: oklch(0.6 0.2 250);
  --color-primary-foreground: oklch(1 0 0);

  --color-secondary: oklch(0.95 0.02 250);
  --color-secondary-foreground: oklch(0.2 0.02 250);

  --color-muted: oklch(0.95 0.01 250);
  --color-muted-foreground: oklch(0.4 0.02 250);

  --color-accent: oklch(0.95 0.03 250);
  --color-accent-foreground: oklch(0.2 0.02 250);

  --color-destructive: oklch(0.5 0.2 25);
  --color-destructive-foreground: oklch(1 0 0);

  --color-border: oklch(0.9 0.01 250);
  --color-input: oklch(0.9 0.01 250);
  --color-ring: oklch(0.6 0.2 250);

  --color-card: oklch(1 0 0);
  --color-card-foreground: oklch(0.1 0 0);

  --color-popover: oklch(1 0 0);
  --color-popover-foreground: oklch(0.1 0 0);

  /* Typography */
  --font-sans: "Inter", ui-sans-serif, system-ui, sans-serif;
  --font-mono: "JetBrains Mono", ui-monospace, monospace;

  /* Font sizes with line heights */
  --text-xs: 0.75rem;
  --text-xs--line-height: 1rem;
  --text-sm: 0.875rem;
  --text-sm--line-height: 1.25rem;
  --text-base: 1rem;
  --text-base--line-height: 1.5rem;
  --text-lg: 1.125rem;
  --text-lg--line-height: 1.75rem;
  --text-xl: 1.25rem;
  --text-xl--line-height: 1.75rem;
  --text-2xl: 1.5rem;
  --text-2xl--line-height: 2rem;
  --text-3xl: 1.875rem;
  --text-3xl--line-height: 2.25rem;
  --text-4xl: 2.25rem;
  --text-4xl--line-height: 2.5rem;

  /* Spacing scale */
  --spacing-px: 1px;
  --spacing-0: 0px;
  --spacing-0_5: 0.125rem;
  --spacing-1: 0.25rem;
  --spacing-1_5: 0.375rem;
  --spacing-2: 0.5rem;
  --spacing-2_5: 0.625rem;
  --spacing-3: 0.75rem;
  --spacing-3_5: 0.875rem;
  --spacing-4: 1rem;
  --spacing-5: 1.25rem;
  --spacing-6: 1.5rem;
  --spacing-7: 1.75rem;
  --spacing-8: 2rem;
  --spacing-9: 2.25rem;
  --spacing-10: 2.5rem;
  --spacing-12: 3rem;
  --spacing-14: 3.5rem;
  --spacing-16: 4rem;
  --spacing-20: 5rem;
  --spacing-24: 6rem;
  --spacing-28: 7rem;
  --spacing-32: 8rem;

  /* Border radius */
  --radius-none: 0;
  --radius-sm: 0.125rem;
  --radius-md: 0.375rem;
  --radius-lg: 0.5rem;
  --radius-xl: 0.75rem;
  --radius-2xl: 1rem;
  --radius-3xl: 1.5rem;
  --radius-full: 9999px;

  /* Shadows */
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  --shadow-xl: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);

  /* Transitions */
  --transition-fast: 150ms;
  --transition-normal: 200ms;
  --transition-slow: 300ms;

  /* Z-index scale */
  --z-dropdown: 1000;
  --z-sticky: 1020;
  --z-fixed: 1030;
  --z-modal-backdrop: 1040;
  --z-modal: 1050;
  --z-popover: 1060;
  --z-tooltip: 1070;
}

/* Dark mode overrides */
.dark {
  --color-background: oklch(0.1 0 0);
  --color-foreground: oklch(0.95 0 0);

  --color-primary: oklch(0.7 0.15 250);
  --color-primary-foreground: oklch(0.1 0 0);

  --color-secondary: oklch(0.2 0.02 250);
  --color-secondary-foreground: oklch(0.95 0.02 250);

  --color-muted: oklch(0.2 0.01 250);
  --color-muted-foreground: oklch(0.6 0.02 250);

  --color-accent: oklch(0.2 0.03 250);
  --color-accent-foreground: oklch(0.95 0.02 250);

  --color-card: oklch(0.15 0 0);
  --color-card-foreground: oklch(0.95 0 0);

  --color-border: oklch(0.25 0.01 250);
  --color-input: oklch(0.25 0.01 250);
}

/* Base styles */
@layer base {
  * {
    @apply border-border;
  }

  body {
    @apply bg-background text-foreground;
    font-feature-settings: "rlig" 1, "calt" 1;
  }

  /* Focus visible for accessibility */
  :focus-visible {
    @apply outline-none ring-2 ring-ring ring-offset-2 ring-offset-background;
  }
}
```

## Container Queries

Container queries allow styling based on parent container size, not viewport.

### Setup Container

```html
<!-- Define a container -->
<div class="@container">
  <!-- Children can query container size -->
  <div class="@md:flex @md:gap-4">
    <div class="@md:w-1/2">Content</div>
    <div class="@md:w-1/2">Sidebar</div>
  </div>
</div>

<!-- Named container for specific queries -->
<div class="@container/card">
  <div class="@lg/card:grid @lg/card:grid-cols-2">
    Content
  </div>
</div>
```

### Container Query Breakpoints

```css
/* Default container breakpoints */
@theme {
  --container-3xs: 16rem;   /* 256px */
  --container-2xs: 18rem;   /* 288px */
  --container-xs: 20rem;    /* 320px */
  --container-sm: 24rem;    /* 384px */
  --container-md: 28rem;    /* 448px */
  --container-lg: 32rem;    /* 512px */
  --container-xl: 36rem;    /* 576px */
  --container-2xl: 42rem;   /* 672px */
  --container-3xl: 48rem;   /* 768px */
  --container-4xl: 56rem;   /* 896px */
  --container-5xl: 64rem;   /* 1024px */
  --container-6xl: 72rem;   /* 1152px */
  --container-7xl: 80rem;   /* 1280px */
}
```

### Practical Container Query Examples

```tsx
// components/ProductCard.tsx
export function ProductCard({ product }: Props) {
  return (
    // Card is its own container
    <article className="@container rounded-lg border bg-card p-4">
      <div className="flex flex-col @sm:flex-row @sm:gap-4">
        {/* Image: Full width on small, fixed on larger */}
        <div className="@sm:w-32 @sm:shrink-0">
          <img
            src={product.image}
            alt={product.name}
            className="w-full aspect-square object-cover rounded"
          />
        </div>

        {/* Content: Stack on small, beside image on larger */}
        <div className="mt-4 @sm:mt-0 flex-1">
          <h3 className="font-semibold @md:text-lg">{product.name}</h3>

          {/* Description hidden on very small containers */}
          <p className="hidden @xs:block text-sm text-muted-foreground mt-1">
            {product.description}
          </p>

          {/* Price and action: Stack on small, row on larger */}
          <div className="mt-4 flex flex-col @md:flex-row @md:items-center @md:justify-between gap-2">
            <span className="text-lg font-bold">${product.price}</span>
            <button className="px-4 py-2 bg-primary text-primary-foreground rounded">
              Add to Cart
            </button>
          </div>
        </div>
      </div>
    </article>
  );
}

// Works in any container size
<div className="w-64">
  <ProductCard product={product} /> <!-- Compact layout -->
</div>

<div className="w-96">
  <ProductCard product={product} /> <!-- Horizontal layout -->
</div>

<div className="w-full max-w-2xl">
  <ProductCard product={product} /> <!-- Full layout -->
</div>
```

## @source Directive for Build Optimization

The `@source` directive tells Tailwind where to look for classes.

```css
/* globals.css */
@import "tailwindcss";

/* Scan specific directories */
@source "../components/**/*.{astro,tsx,jsx}";
@source "../layouts/**/*.astro";
@source "../pages/**/*.{astro,tsx,mdx}";

/* Scan node_modules for specific packages */
@source "../../node_modules/@radix-ui/react-*/**/*.js";

/* Exclude test files */
@source "../**/*.{astro,tsx}" not "../**/*.test.{ts,tsx}";
```

### Benefits of @source

1. **Faster builds** — Only scan necessary files
1. **Smaller output** — Don't include unused classes from dependencies
1. **Explicit dependencies** — Know exactly what's being scanned

## Component Variants with CVA

Class Variance Authority (CVA) creates type-safe component variants.

```bash
bun add class-variance-authority
```

```tsx
// components/ui/button.tsx
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  // Base styles
  'inline-flex items-center justify-center rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50',
  {
    variants: {
      variant: {
        default: 'bg-primary text-primary-foreground hover:bg-primary/90',
        destructive: 'bg-destructive text-destructive-foreground hover:bg-destructive/90',
        outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
        secondary: 'bg-secondary text-secondary-foreground hover:bg-secondary/80',
        ghost: 'hover:bg-accent hover:text-accent-foreground',
        link: 'text-primary underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-10 px-4 py-2',
        sm: 'h-9 rounded-md px-3',
        lg: 'h-11 rounded-md px-8',
        icon: 'h-10 w-10',
      },
    },
    // Compound variants for specific combinations
    compoundVariants: [
      {
        variant: 'outline',
        size: 'sm',
        className: 'border-2',
      },
    ],
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

export function Button({
  className,
  variant,
  size,
  asChild = false,
  ...props
}: ButtonProps) {
  return (
    <button
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    />
  );
}

// Usage
<Button>Default</Button>
<Button variant="destructive" size="lg">Delete</Button>
<Button variant="outline" size="sm">Cancel</Button>
<Button variant="ghost" size="icon"><Icon /></Button>
```

### Complex Card Variants

```tsx
// components/ui/card.tsx
import { cva, type VariantProps } from 'class-variance-authority';

const cardVariants = cva(
  'rounded-lg border bg-card text-card-foreground',
  {
    variants: {
      variant: {
        default: 'border-border',
        elevated: 'border-transparent shadow-lg',
        outline: 'border-2 border-border',
        ghost: 'border-transparent bg-transparent',
      },
      padding: {
        none: 'p-0',
        sm: 'p-4',
        default: 'p-6',
        lg: 'p-8',
      },
      interactive: {
        true: 'cursor-pointer transition-all hover:shadow-md hover:border-primary/50',
        false: '',
      },
    },
    compoundVariants: [
      {
        variant: 'elevated',
        interactive: true,
        className: 'hover:shadow-xl',
      },
    ],
    defaultVariants: {
      variant: 'default',
      padding: 'default',
      interactive: false,
    },
  }
);

interface CardProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof cardVariants> {}

export function Card({ className, variant, padding, interactive, ...props }: CardProps) {
  return (
    <div
      className={cn(cardVariants({ variant, padding, interactive, className }))}
      {...props}
    />
  );
}
```

## Typography Plugin

For long-form content like blog posts and documentation.

```bash
bun add @tailwindcss/typography
```

```css
/* globals.css */
@plugin "@tailwindcss/typography";
```

### Usage

```astro
---
// src/pages/blog/[slug].astro
const { Content } = await post.render();
---

<article class="prose prose-lg dark:prose-invert max-w-none">
  <Content />
</article>
```

### Customizing Typography

```css
/* globals.css */
@layer components {
  .prose {
    --tw-prose-body: theme('colors.foreground');
    --tw-prose-headings: theme('colors.foreground');
    --tw-prose-lead: theme('colors.muted-foreground');
    --tw-prose-links: theme('colors.primary');
    --tw-prose-bold: theme('colors.foreground');
    --tw-prose-counters: theme('colors.muted-foreground');
    --tw-prose-bullets: theme('colors.muted-foreground');
    --tw-prose-hr: theme('colors.border');
    --tw-prose-quotes: theme('colors.foreground');
    --tw-prose-quote-borders: theme('colors.border');
    --tw-prose-captions: theme('colors.muted-foreground');
    --tw-prose-code: theme('colors.foreground');
    --tw-prose-pre-code: theme('colors.foreground');
    --tw-prose-pre-bg: theme('colors.muted');
    --tw-prose-th-borders: theme('colors.border');
    --tw-prose-td-borders: theme('colors.border');
  }

  /* Custom prose modifications */
  .prose :where(code):not(:where([class~="not-prose"] *)) {
    @apply bg-muted px-1.5 py-0.5 rounded font-mono text-sm;
  }

  .prose :where(code):not(:where([class~="not-prose"] *))::before,
  .prose :where(code):not(:where([class~="not-prose"] *))::after {
    content: none;
  }

  .prose :where(a):not(:where([class~="not-prose"] *)) {
    @apply text-primary no-underline hover:underline;
  }
}
```

## Accessibility Utilities

### Focus States

```html
<!-- Focus visible for keyboard users only -->
<button class="focus:outline-none focus-visible:ring-2 focus-visible:ring-primary">
  Click me
</button>

<!-- Focus within for containers -->
<div class="focus-within:ring-2 focus-within:ring-primary rounded-lg">
  <input type="text" class="focus:outline-none" />
</div>
```

### Screen Reader Utilities

```html
<!-- Visually hidden but accessible to screen readers -->
<span class="sr-only">Close menu</span>

<!-- Skip to main content link -->
<a href="#main" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded">
  Skip to main content
</a>
```

### Reduced Motion

```html
<!-- Disable animations for users who prefer reduced motion -->
<div class="animate-bounce motion-reduce:animate-none">
  Bouncing element
</div>

<!-- Alternative for reduced motion -->
<div class="transition-transform hover:scale-105 motion-reduce:hover:scale-100 motion-reduce:transition-none">
  Hover effect
</div>
```

### High Contrast

```css
/* globals.css */
@layer utilities {
  /* Force colors for high contrast mode */
  @media (forced-colors: active) {
    .forced-color-adjust-none {
      forced-color-adjust: none;
    }

    .forced-color-adjust-auto {
      forced-color-adjust: auto;
    }
  }
}
```

## Dark Mode

### Class Strategy (Recommended)

```javascript
// astro.config.mjs - Tailwind handles this automatically with class strategy
```

```tsx
// components/ThemeToggle.tsx
import { useState, useEffect } from 'react';

export function ThemeToggle() {
  const [theme, setTheme] = useState<'light' | 'dark'>('light');

  useEffect(() => {
    // Check localStorage or system preference
    const stored = localStorage.getItem('theme');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    const initial = stored || (systemPrefersDark ? 'dark' : 'light');
    setTheme(initial as 'light' | 'dark');
    document.documentElement.classList.toggle('dark', initial === 'dark');
  }, []);

  const toggle = () => {
    const next = theme === 'light' ? 'dark' : 'light';
    setTheme(next);
    localStorage.setItem('theme', next);
    document.documentElement.classList.toggle('dark', next === 'dark');
  };

  return (
    <button onClick={toggle} aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}>
      {theme === 'light' ? '🌙' : '☀️'}
    </button>
  );
}
```

### Prevent Flash of Wrong Theme

```astro
---
// src/layouts/BaseLayout.astro
---
<html lang="en">
  <head>
    <!-- Inline script to set theme before render -->
    <script is:inline>
      const theme = localStorage.getItem('theme') ||
        (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
      document.documentElement.classList.toggle('dark', theme === 'dark');
    </script>
  </head>
  <body>
    <slot />
  </body>
</html>
```

## Prettier Plugin

Automatically sort Tailwind classes.

```bash
bun add -d prettier prettier-plugin-tailwindcss
```

```json
// .prettierrc
{
  "plugins": ["prettier-plugin-tailwindcss"],
  "tailwindFunctions": ["cn", "cva", "clsx"]
}
```

## Visual Regression Testing

### Setup Playwright for Visual Tests

```typescript
// playwright.config.ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests/visual',
  snapshotDir: './tests/visual/__snapshots__',
  updateSnapshots: 'missing',
  projects: [
    {
      name: 'Desktop Chrome',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'Mobile Safari',
      use: { ...devices['iPhone 13'] },
    },
  ],
});
```

### Visual Test Examples

```typescript
// tests/visual/components.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Visual Regression', () => {
  test('homepage renders correctly', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveScreenshot('homepage.png', {
      fullPage: true,
    });
  });

  test('buttons match design', async ({ page }) => {
    await page.goto('/design-system/buttons');

    // Screenshot specific component
    const buttons = page.locator('[data-testid="button-showcase"]');
    await expect(buttons).toHaveScreenshot('buttons.png');
  });

  test('dark mode renders correctly', async ({ page }) => {
    await page.goto('/');

    // Enable dark mode
    await page.evaluate(() => {
      document.documentElement.classList.add('dark');
    });

    await expect(page).toHaveScreenshot('homepage-dark.png', {
      fullPage: true,
    });
  });

  test('responsive layouts', async ({ page }) => {
    await page.goto('/products');

    // Desktop
    await page.setViewportSize({ width: 1280, height: 720 });
    await expect(page).toHaveScreenshot('products-desktop.png');

    // Tablet
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(page).toHaveScreenshot('products-tablet.png');

    // Mobile
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page).toHaveScreenshot('products-mobile.png');
  });
});
```

### CI Integration

```yaml
# .github/workflows/visual-regression.yml
name: Visual Regression

on:
  pull_request:
    branches: [main]

jobs:
  visual-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: oven-sh/setup-bun@v1

      - name: Install dependencies
        run: bun install

      - name: Build
        run: bun run build

      - name: Install Playwright
        run: bunx playwright install --with-deps chromium

      - name: Run visual tests
        run: bunx playwright test tests/visual

      - name: Upload diff artifacts
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: visual-diff
          path: test-results/
```

## Utility Patterns

### cn() Helper

```typescript
// lib/utils.ts
import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Usage
cn('px-4 py-2', condition && 'bg-primary', className);
cn('text-red-500', 'text-blue-500'); // Returns 'text-blue-500' (merged)
```

### Responsive Patterns

```html
<!-- Mobile-first: base styles for mobile, overrides for larger -->
<div class="
  flex flex-col gap-4
  md:flex-row md:gap-6
  lg:gap-8
">
  Content
</div>

<!-- Grid that adapts -->
<div class="
  grid grid-cols-1 gap-4
  sm:grid-cols-2
  lg:grid-cols-3
  xl:grid-cols-4
">
  {items.map(item => <Card item={item} />)}
</div>
```

### Animation Utilities

```css
/* globals.css */
@layer utilities {
  .animate-in {
    animation: animate-in 0.2s ease-out;
  }

  .animate-out {
    animation: animate-out 0.2s ease-in;
  }

  @keyframes animate-in {
    from {
      opacity: 0;
      transform: translateY(-10px);
    }
    to {
      opacity: 1;
      transform: translateY(0);
    }
  }

  @keyframes animate-out {
    from {
      opacity: 1;
      transform: translateY(0);
    }
    to {
      opacity: 0;
      transform: translateY(-10px);
    }
  }
}
```

## Common Issues

| Issue | Solution |
|-------|----------|
| Classes not applying | Check @source includes your files |
| Dark mode not working | Ensure `dark` class on `<html>` |
| Custom colors not working | Verify @theme syntax in globals.css |
| PurgeCSS removing classes | Use complete class names, not dynamic |
| Container queries not working | Add `@container` to parent element |
| Typography plugin issues | Check @plugin directive placement |
