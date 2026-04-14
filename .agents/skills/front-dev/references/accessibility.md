# Accessibility Reference

## Overview

Web accessibility ensures that websites work for everyone, including people with
disabilities. This guide covers WCAG 2.1 AA compliance for Astro + React/Preact
applications.

## Core Principles (POUR)

1. **Perceivable** — Content can be perceived by all senses
1. **Operable** — Interface can be operated by all users
1. **Understandable** — Content and operation are understandable
1. **Robust** — Content works with assistive technologies

## Semantic HTML

### Use Correct Elements

```astro
---
// src/pages/index.astro
---

<!-- Good: Semantic structure -->
<header>
  <nav aria-label="Main navigation">
    <ul>
      <li><a href="/">Home</a></li>
      <li><a href="/about">About</a></li>
    </ul>
  </nav>
</header>

<main id="main-content">
  <article>
    <h1>Page Title</h1>
    <p>Introduction paragraph...</p>

    <section aria-labelledby="features-heading">
      <h2 id="features-heading">Features</h2>
      <ul>
        <li>Feature 1</li>
        <li>Feature 2</li>
      </ul>
    </section>
  </article>

  <aside aria-label="Related content">
    <h2>Related Articles</h2>
    <!-- ... -->
  </aside>
</main>

<footer>
  <nav aria-label="Footer navigation">
    <!-- ... -->
  </nav>
</footer>

<!-- Bad: Divs for everything -->
<div class="header">
  <div class="nav">
    <div class="link">Home</div>
  </div>
</div>
```

### Heading Hierarchy

```astro
<!-- Good: Proper hierarchy -->
<h1>Main Page Title</h1>
  <h2>Section 1</h2>
    <h3>Subsection 1.1</h3>
    <h3>Subsection 1.2</h3>
  <h2>Section 2</h2>
    <h3>Subsection 2.1</h3>

<!-- Bad: Skipping levels -->
<h1>Title</h1>
<h3>Skipped h2!</h3>
<h5>Skipped h4!</h5>
```

### Interactive Elements

```tsx
// Good: Correct elements for interactions
<button onClick={handleClick}>Click me</button>
<a href="/page">Go to page</a>

// Bad: Divs with click handlers
<div onClick={handleClick}>Click me</div>
<span onClick={() => navigate('/page')}>Go to page</span>

// If you must use non-semantic elements, add roles
<div
  role="button"
  tabIndex={0}
  onClick={handleClick}
  onKeyDown={(e) => e.key === 'Enter' && handleClick()}
>
  Click me
</div>
```

## Skip Links

Allow keyboard users to skip repetitive content:

```astro
---
// src/layouts/BaseLayout.astro
---
<body>
  <!-- Skip link: first focusable element -->
  <a
    href="#main-content"
    class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded"
  >
    Skip to main content
  </a>

  <header><!-- Navigation --></header>

  <main id="main-content" tabindex="-1">
    <slot />
  </main>

  <footer><!-- Footer --></footer>
</body>
```

```css
/* Tailwind sr-only class (already included) */
.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}
```

## Focus Management

### Visible Focus Styles

```css
/* globals.css */
@layer base {
  /* Visible focus for all interactive elements */
  :focus-visible {
    @apply outline-none ring-2 ring-ring ring-offset-2 ring-offset-background;
  }

  /* Remove default outline when using our styles */
  :focus:not(:focus-visible) {
    outline: none;
  }
}
```

```tsx
// Component with explicit focus styles
<Button className="focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2">
  Click me
</Button>

// Input with focus styles
<Input className="focus-visible:ring-2 focus-visible:ring-ring focus-visible:border-primary" />
```

### Focus Trap for Modals

```tsx
// components/Dialog.tsx
import { useEffect, useRef, type ReactNode } from 'react';

interface DialogProps {
  isOpen: boolean;
  onClose: () => void;
  children: ReactNode;
}

export function Dialog({ isOpen, onClose, children }: DialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (isOpen) {
      // Store current focus
      previousFocus.current = document.activeElement as HTMLElement;

      // Focus dialog
      dialogRef.current?.focus();

      // Get focusable elements
      const focusableSelector = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

      const handleKeyDown = (e: KeyboardEvent) => {
        if (e.key === 'Escape') {
          onClose();
          return;
        }

        if (e.key === 'Tab') {
          const focusable = dialogRef.current?.querySelectorAll(focusableSelector);
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
    }
  }, [isOpen, onClose]);

  // Restore focus on close
  useEffect(() => {
    if (!isOpen && previousFocus.current) {
      previousFocus.current.focus();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Dialog */}
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        className="relative bg-background rounded-lg p-6 max-w-md w-full mx-4"
      >
        {children}
      </div>
    </div>
  );
}
```

### Focus on Route Change (Astro)

```astro
---
// src/layouts/BaseLayout.astro
---
<main id="main-content" tabindex="-1">
  <slot />
</main>

<script>
  // Focus main content on navigation
  document.addEventListener('astro:page-load', () => {
    const main = document.getElementById('main-content');
    if (main) {
      main.focus();
    }
  });
</script>
```

## ARIA Attributes

### When to Use ARIA

1. **First choice:** Use semantic HTML elements
1. **Second choice:** Add ARIA if native elements are insufficient
1. **Rule:** No ARIA is better than bad ARIA

### Common ARIA Patterns

```tsx
// Live regions for dynamic content
<div aria-live="polite" aria-atomic="true">
  {message && <p>{message}</p>}
</div>

// Loading states
<button aria-busy={isLoading} disabled={isLoading}>
  {isLoading ? 'Loading...' : 'Submit'}
</button>

// Expanded/collapsed
<button
  aria-expanded={isOpen}
  aria-controls="menu-content"
  onClick={toggle}
>
  Menu
</button>
<div id="menu-content" hidden={!isOpen}>
  {/* Menu items */}
</div>

// Current page in navigation
<nav>
  <a href="/" aria-current={pathname === '/' ? 'page' : undefined}>Home</a>
  <a href="/about" aria-current={pathname === '/about' ? 'page' : undefined}>About</a>
</nav>

// Labels for icon buttons
<button aria-label="Close dialog">
  <XIcon className="h-4 w-4" aria-hidden="true" />
</button>

// Descriptions
<input
  type="password"
  aria-describedby="password-requirements"
/>
<p id="password-requirements" className="text-sm text-muted-foreground">
  Password must be at least 8 characters with uppercase and number.
</p>

// Invalid state
<input
  type="email"
  aria-invalid={!!error}
  aria-describedby={error ? 'email-error' : undefined}
/>
{error && <p id="email-error" className="text-destructive">{error}</p>}
```

### ARIA Roles

```tsx
// Custom components that need roles
<div role="tablist">
  <button role="tab" aria-selected={active === 0}>Tab 1</button>
  <button role="tab" aria-selected={active === 1}>Tab 2</button>
</div>
<div role="tabpanel">Content</div>

// Alert for important messages
<div role="alert">
  Form submitted successfully!
</div>

// Status for non-critical updates
<div role="status">
  3 items in cart
</div>

// Search landmark
<form role="search">
  <input type="search" />
</form>
```

## Images and Media

### Image Alternatives

```astro
<!-- Informative image: Describe the content -->
<img
  src="/chart.png"
  alt="Sales increased 25% from Q1 to Q2, reaching $1.2M"
/>

<!-- Decorative image: Empty alt -->
<img src="/decorative-pattern.svg" alt="" role="presentation" />

<!-- Complex image: Use aria-describedby -->
<figure>
  <img
    src="/complex-diagram.png"
    alt="System architecture diagram"
    aria-describedby="diagram-description"
  />
  <figcaption id="diagram-description">
    The system consists of three main components: a frontend server,
    an API gateway, and a database cluster. The frontend connects to
    the API gateway via HTTPS, which then queries the database cluster.
  </figcaption>
</figure>

<!-- Icon with meaning -->
<span aria-label="Warning">⚠️</span>

<!-- Icon purely decorative -->
<span aria-hidden="true">🎉</span>
```

### Video and Audio

```tsx
// Video with captions
<video controls>
  <source src="/video.mp4" type="video/mp4" />
  <track
    kind="captions"
    src="/captions.vtt"
    srcLang="en"
    label="English"
    default
  />
  <p>Your browser doesn't support video. <a href="/video.mp4">Download</a></p>
</video>

// Audio with transcript
<figure>
  <audio controls>
    <source src="/podcast.mp3" type="audio/mpeg" />
  </audio>
  <figcaption>
    <details>
      <summary>View transcript</summary>
      <p>...</p>
    </details>
  </figcaption>
</figure>
```

## Forms

### Accessible Form Pattern

```tsx
// components/AccessibleForm.tsx
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';

const schema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Please enter a valid email'),
});

export function AccessibleForm() {
  const { register, handleSubmit, formState: { errors } } = useForm({
    resolver: zodResolver(schema),
  });

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate>
      {/* Text input with label and error */}
      <div className="space-y-2">
        <label htmlFor="name" className="text-sm font-medium">
          Name <span aria-hidden="true">*</span>
          <span className="sr-only">(required)</span>
        </label>
        <input
          id="name"
          type="text"
          {...register('name')}
          aria-invalid={!!errors.name}
          aria-describedby={errors.name ? 'name-error' : undefined}
          className="w-full px-3 py-2 border rounded-md"
        />
        {errors.name && (
          <p id="name-error" className="text-sm text-destructive" role="alert">
            {errors.name.message}
          </p>
        )}
      </div>

      {/* Email with description */}
      <div className="space-y-2">
        <label htmlFor="email" className="text-sm font-medium">
          Email <span aria-hidden="true">*</span>
          <span className="sr-only">(required)</span>
        </label>
        <input
          id="email"
          type="email"
          {...register('email')}
          aria-invalid={!!errors.email}
          aria-describedby="email-hint email-error"
          className="w-full px-3 py-2 border rounded-md"
        />
        <p id="email-hint" className="text-sm text-muted-foreground">
          We'll never share your email.
        </p>
        {errors.email && (
          <p id="email-error" className="text-sm text-destructive" role="alert">
            {errors.email.message}
          </p>
        )}
      </div>

      <button type="submit" className="px-4 py-2 bg-primary text-primary-foreground rounded">
        Submit
      </button>
    </form>
  );
}
```

### Form Validation Announcements

```tsx
// Announce errors to screen readers
function FormWithAnnouncements() {
  const [announcement, setAnnouncement] = useState('');

  function onError(errors: FieldErrors) {
    const errorCount = Object.keys(errors).length;
    setAnnouncement(`Form has ${errorCount} error${errorCount > 1 ? 's' : ''}. Please correct and try again.`);
  }

  return (
    <>
      {/* Live region for announcements */}
      <div
        role="status"
        aria-live="polite"
        aria-atomic="true"
        className="sr-only"
      >
        {announcement}
      </div>

      <form onSubmit={handleSubmit(onSubmit, onError)}>
        {/* Form fields */}
      </form>
    </>
  );
}
```

## Color and Contrast

### Minimum Contrast Ratios

- **Normal text:** 4.5:1 (WCAG AA)
- **Large text (18px+ or 14px+ bold):** 3:1
- **UI components and graphics:** 3:1

### Don't Rely on Color Alone

```tsx
// Bad: Color only indicates state
<span className={isError ? 'text-red-500' : 'text-green-500'}>
  {message}
</span>

// Good: Color + icon + text
<span className={isError ? 'text-destructive' : 'text-green-600'}>
  {isError ? '❌ Error: ' : '✓ Success: '}
  {message}
</span>

// Good: Color + pattern for charts
<div className="flex gap-4">
  <div className="bg-primary" style={{ backgroundImage: 'url(pattern1.svg)' }}>
    Series 1
  </div>
  <div className="bg-secondary" style={{ backgroundImage: 'url(pattern2.svg)' }}>
    Series 2
  </div>
</div>
```

### Focus Indicators

```css
/* High contrast focus indicator */
:focus-visible {
  outline: 2px solid var(--ring);
  outline-offset: 2px;
}

/* Or use a ring */
.focus-visible\:ring-2:focus-visible {
  --tw-ring-width: 2px;
  box-shadow: var(--tw-ring-inset) 0 0 0 calc(var(--tw-ring-width) + var(--tw-ring-offset-width)) var(--tw-ring-color);
}
```

## Reduced Motion

Respect user preferences for reduced motion:

```tsx
// Check preference in JavaScript
const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

// In React
function AnimatedComponent() {
  const prefersReducedMotion = useMediaQuery('(prefers-reduced-motion: reduce)');

  return (
    <div
      className={prefersReducedMotion ? '' : 'animate-bounce'}
    >
      Content
    </div>
  );
}
```

```css
/* Tailwind utilities */
.motion-reduce\:animate-none {
  animation: none;
}

.motion-reduce\:transition-none {
  transition: none;
}

/* Usage */
<div class="animate-pulse motion-reduce:animate-none">
  Loading...
</div>

<button class="transition-transform hover:scale-105 motion-reduce:transform-none motion-reduce:transition-none">
  Hover me
</button>
```

```css
/* Global reduction */
@media (prefers-reduced-motion: reduce) {
  *,
  *::before,
  *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
```

## Keyboard Navigation

### Keyboard Patterns

| Key | Action |
|-----|--------|
| `Tab` | Move to next focusable element |
| `Shift + Tab` | Move to previous focusable element |
| `Enter` | Activate buttons, links |
| `Space` | Activate buttons, checkboxes |
| `Escape` | Close modals, menus |
| `Arrow keys` | Navigate within components |

### Custom Keyboard Navigation

```tsx
// components/RadioGroup.tsx
function RadioGroup({ options, value, onChange }: Props) {
  const [focusedIndex, setFocusedIndex] = useState(0);

  function handleKeyDown(e: React.KeyboardEvent) {
    let newIndex = focusedIndex;

    switch (e.key) {
      case 'ArrowDown':
      case 'ArrowRight':
        e.preventDefault();
        newIndex = (focusedIndex + 1) % options.length;
        break;
      case 'ArrowUp':
      case 'ArrowLeft':
        e.preventDefault();
        newIndex = (focusedIndex - 1 + options.length) % options.length;
        break;
      case ' ':
      case 'Enter':
        e.preventDefault();
        onChange(options[focusedIndex].value);
        break;
    }

    setFocusedIndex(newIndex);
  }

  return (
    <div
      role="radiogroup"
      aria-labelledby="group-label"
      onKeyDown={handleKeyDown}
    >
      <span id="group-label" className="sr-only">Select an option</span>
      {options.map((option, index) => (
        <div
          key={option.value}
          role="radio"
          aria-checked={value === option.value}
          tabIndex={index === focusedIndex ? 0 : -1}
          onClick={() => onChange(option.value)}
          className="cursor-pointer p-2 focus:ring-2"
        >
          {option.label}
        </div>
      ))}
    </div>
  );
}
```

## Testing Accessibility

### Manual Testing Checklist

1. **Keyboard Navigation**
    - [ ] Can reach all interactive elements with Tab
    - [ ] Focus order is logical
    - [ ] Focus is visible at all times
    - [ ] Can operate all controls with keyboard

1. **Screen Reader**
    - [ ] All images have appropriate alt text
    - [ ] Form fields have labels
    - [ ] Headings form logical hierarchy
    - [ ] Dynamic content is announced

1. **Visual**
    - [ ] Color contrast meets requirements
    - [ ] Information not conveyed by color alone
    - [ ] Text resizes without loss of functionality

### Automated Testing

```typescript
// Using jest-axe
import { axe, toHaveNoViolations } from 'jest-axe';

expect.extend(toHaveNoViolations);

test('component has no accessibility violations', async () => {
  const { container } = render(<MyComponent />);
  const results = await axe(container);
  expect(results).toHaveNoViolations();
});

// Using Playwright + axe-core
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('page has no accessibility violations', async ({ page }) => {
  await page.goto('/');
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
```

### Screen Readers to Test

- **macOS:** VoiceOver (built-in, Cmd + F5)
- **Windows:** NVDA (free), JAWS
- **iOS:** VoiceOver (built-in)
- **Android:** TalkBack (built-in)

## Accessibility Checklist

### Page Level

- [ ] Page has descriptive `<title>`
- [ ] Language is declared (`<html lang="en">`)
- [ ] Skip link is first focusable element
- [ ] Landmarks are used (`<header>`, `<nav>`, `<main>`, `<footer>`)
- [ ] One `<h1>` per page
- [ ] Heading hierarchy is logical

### Components

- [ ] Interactive elements are focusable
- [ ] Focus is visible
- [ ] Buttons have accessible names
- [ ] Links have descriptive text
- [ ] Images have alt text
- [ ] Form fields have labels
- [ ] Error messages are associated with fields
- [ ] Loading states are announced

### Dynamic Content

- [ ] Live regions announce updates
- [ ] Focus is managed for modals
- [ ] Focus returns after modal closes
- [ ] SPA navigation announces page changes

### Media

- [ ] Videos have captions
- [ ] Audio has transcripts
- [ ] Animations respect reduced motion

## Resources

- [WCAG 2.1 Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)
- [MDN Accessibility](https://developer.mozilla.org/en-US/docs/Web/Accessibility)
- [A11y Project Checklist](https://www.a11yproject.com/checklist/)
- [axe DevTools Extension](https://www.deque.com/axe/devtools/)
