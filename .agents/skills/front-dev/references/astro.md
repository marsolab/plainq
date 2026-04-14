# Astro Reference

## Overview

Astro is a web framework for content-driven websites. It renders pages to static
HTML by default and only hydrates interactive components (islands) when needed.
**Astro is always our foundation — React/Preact are added as islands.**

## Project Setup

```bash
# Create new project
bun create astro@latest my-site
cd my-site

# Add integrations
bunx astro add react      # React islands
bunx astro add tailwind   # Tailwind CSS
bunx astro add mdx        # MDX support
bunx astro add sitemap    # Auto-generate sitemap
bunx astro add partytown  # Third-party script isolation

# Start development
bun run dev
```

## Project Structure

```text
src/
├── pages/              # File-based routing
│   ├── index.astro
│   ├── about.astro
│   ├── blog/
│   │   ├── index.astro
│   │   └── [slug].astro
│   └── api/
│       └── contact.ts  # API endpoints
├── layouts/            # Page layouts
│   ├── BaseLayout.astro
│   └── BlogLayout.astro
├── components/         # UI components
│   ├── Header.astro    # Static Astro components
│   ├── Footer.astro
│   ├── Card.astro
│   └── Counter.tsx     # React islands
├── content/            # Content Collections
│   ├── config.ts       # Collection schemas
│   └── blog/
│       ├── first-post.md
│       └── second-post.mdx
├── styles/
│   └── globals.css
└── lib/                # Utilities
    └── utils.ts
```

## Content Collections with Zod

### Define Collection Schema

```typescript
// src/content/config.ts
import { defineCollection, z } from 'astro:content';

// Blog posts collection
const blog = defineCollection({
  type: 'content', // Markdown/MDX
  schema: ({ image }) => z.object({
    title: z.string().max(100),
    description: z.string().max(200),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    author: z.string().default('Anonymous'),
    tags: z.array(z.string()).default([]),
    draft: z.boolean().default(false),
    // Image with automatic optimization
    heroImage: image().optional(),
    // External image URL
    ogImage: z.string().url().optional(),
    // Related posts
    relatedPosts: z.array(z.string()).optional(),
    // Reading time (computed in frontmatter)
    readingTime: z.string().optional(),
    // SEO
    canonicalUrl: z.string().url().optional(),
    noindex: z.boolean().default(false),
  }),
});

// Authors collection (data, not content)
const authors = defineCollection({
  type: 'data', // JSON/YAML
  schema: ({ image }) => z.object({
    name: z.string(),
    email: z.string().email(),
    bio: z.string().max(500),
    avatar: image(),
    social: z.object({
      twitter: z.string().optional(),
      github: z.string().optional(),
      linkedin: z.string().url().optional(),
    }).optional(),
  }),
});

// Products collection
const products = defineCollection({
  type: 'data',
  schema: z.object({
    name: z.string(),
    price: z.number().positive(),
    category: z.enum(['electronics', 'clothing', 'home']),
    inStock: z.boolean(),
    features: z.array(z.string()),
  }),
});

// Documentation collection with nested categories
const docs = defineCollection({
  type: 'content',
  schema: z.object({
    title: z.string(),
    description: z.string(),
    order: z.number().default(999),
    category: z.string(),
    // Reference to related docs
    seeAlso: z.array(z.string()).optional(),
  }),
});

export const collections = { blog, authors, products, docs };
```

### Query Collections

```astro
---
// src/pages/blog/index.astro
import { getCollection } from 'astro:content';
import BlogLayout from '@/layouts/BlogLayout.astro';
import PostCard from '@/components/PostCard.astro';

// Get all non-draft posts, sorted by date
const posts = await getCollection('blog', ({ data }) => {
  // Filter out drafts in production
  return import.meta.env.PROD ? !data.draft : true;
});

const sortedPosts = posts.sort(
  (a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf()
);

// Get unique tags
const allTags = [...new Set(posts.flatMap(post => post.data.tags))];
---

<BlogLayout title="Blog" description="All blog posts">
  <h1 class="text-4xl font-bold mb-8">Blog</h1>

  <!-- Tag filter (could be a React island for interactivity) -->
  <div class="flex gap-2 mb-8">
    {allTags.map(tag => (
      <a
        href={`/blog/tags/${tag}`}
        class="px-3 py-1 bg-secondary rounded-full text-sm"
      >
        {tag}
      </a>
    ))}
  </div>

  <div class="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
    {sortedPosts.map(post => (
      <PostCard post={post} />
    ))}
  </div>
</BlogLayout>
```

### Dynamic Routes with getStaticPaths

```astro
---
// src/pages/blog/[slug].astro
import { getCollection, type CollectionEntry } from 'astro:content';
import BlogLayout from '@/layouts/BlogLayout.astro';
import TableOfContents from '@/components/TableOfContents.astro';
import RelatedPosts from '@/components/RelatedPosts.astro';
import ShareButtons from '@/components/ShareButtons'; // React island

export async function getStaticPaths() {
  const posts = await getCollection('blog');

  return posts.map(post => ({
    params: { slug: post.slug },
    props: { post },
  }));
}

interface Props {
  post: CollectionEntry<'blog'>;
}

const { post } = Astro.props;
const { Content, headings } = await post.render();

// Get related posts if specified
let relatedPosts: CollectionEntry<'blog'>[] = [];
if (post.data.relatedPosts) {
  const allPosts = await getCollection('blog');
  relatedPosts = allPosts.filter(p =>
    post.data.relatedPosts?.includes(p.slug)
  );
}

// Generate structured data
const jsonLd = {
  '@context': 'https://schema.org',
  '@type': 'BlogPosting',
  headline: post.data.title,
  description: post.data.description,
  datePublished: post.data.pubDate.toISOString(),
  dateModified: post.data.updatedDate?.toISOString() || post.data.pubDate.toISOString(),
  author: {
    '@type': 'Person',
    name: post.data.author,
  },
};
---

<BlogLayout
  title={post.data.title}
  description={post.data.description}
  ogImage={post.data.ogImage}
>
  <script type="application/ld+json" set:html={JSON.stringify(jsonLd)} />

  <article class="max-w-3xl mx-auto">
    <header class="mb-8">
      <h1 class="text-4xl font-bold mb-4">{post.data.title}</h1>
      <div class="flex items-center gap-4 text-muted-foreground">
        <time datetime={post.data.pubDate.toISOString()}>
          {post.data.pubDate.toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric'
          })}
        </time>
        {post.data.readingTime && <span>· {post.data.readingTime}</span>}
        <span>· {post.data.author}</span>
      </div>
      <div class="flex gap-2 mt-4">
        {post.data.tags.map(tag => (
          <a href={`/blog/tags/${tag}`} class="px-2 py-1 bg-secondary rounded text-sm">
            {tag}
          </a>
        ))}
      </div>
    </header>

    {headings.length > 0 && (
      <aside class="mb-8 p-4 bg-muted rounded-lg">
        <TableOfContents headings={headings} />
      </aside>
    )}

    <div class="prose prose-lg max-w-none">
      <Content />
    </div>

    <footer class="mt-12 pt-8 border-t">
      <ShareButtons
        client:visible
        url={Astro.url.href}
        title={post.data.title}
      />

      {relatedPosts.length > 0 && (
        <RelatedPosts posts={relatedPosts} />
      )}
    </footer>
  </article>
</BlogLayout>
```

## MDX Component Authoring

### Configure MDX

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import react from '@astrojs/react';

export default defineConfig({
  integrations: [
    mdx({
      // Syntax highlighting
      syntaxHighlight: 'shiki',
      shikiConfig: {
        theme: 'github-dark',
        wrap: true,
      },
      // Remark plugins for markdown processing
      remarkPlugins: [
        'remark-gfm', // GitHub Flavored Markdown
        'remark-smartypants', // Smart quotes
      ],
      // Rehype plugins for HTML processing
      rehypePlugins: [
        'rehype-slug', // Add IDs to headings
        ['rehype-autolink-headings', { behavior: 'wrap' }],
      ],
      // Global components available in all MDX
      // No import needed in MDX files
    }),
    react(),
  ],
});
```

### Create MDX Components

```tsx
// src/components/mdx/Callout.tsx
import { type ReactNode } from 'react';

interface CalloutProps {
  type?: 'info' | 'warning' | 'error' | 'success';
  title?: string;
  children: ReactNode;
}

const icons = {
  info: 'ℹ️',
  warning: '⚠️',
  error: '❌',
  success: '✅',
};

const styles = {
  info: 'bg-blue-50 border-blue-500 text-blue-900',
  warning: 'bg-yellow-50 border-yellow-500 text-yellow-900',
  error: 'bg-red-50 border-red-500 text-red-900',
  success: 'bg-green-50 border-green-500 text-green-900',
};

export function Callout({ type = 'info', title, children }: CalloutProps) {
  return (
    <aside className={`border-l-4 p-4 my-6 rounded-r ${styles[type]}`}>
      <div className="flex items-center gap-2 font-semibold mb-2">
        <span>{icons[type]}</span>
        {title && <span>{title}</span>}
      </div>
      <div>{children}</div>
    </aside>
  );
}
```

```tsx
// src/components/mdx/CodeBlock.tsx
import { useState } from 'react';
import { Button } from '@/components/ui/button';

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
}

export function CodeBlock({ code, language, filename }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="relative group my-6">
      {filename && (
        <div className="px-4 py-2 bg-muted border-b text-sm font-mono">
          {filename}
        </div>
      )}
      <pre className={`language-${language} p-4 overflow-x-auto`}>
        <code>{code}</code>
      </pre>
      <Button
        size="sm"
        variant="ghost"
        className="absolute top-2 right-2 opacity-0 group-hover:opacity-100"
        onClick={copy}
      >
        {copied ? 'Copied!' : 'Copy'}
      </Button>
    </div>
  );
}
```

```tsx
// src/components/mdx/YouTube.tsx
interface YouTubeProps {
  id: string;
  title?: string;
}

export function YouTube({ id, title = 'YouTube video' }: YouTubeProps) {
  return (
    <div className="relative aspect-video my-6 rounded-lg overflow-hidden">
      <iframe
        src={`https://www.youtube-nocookie.com/embed/${id}`}
        title={title}
        allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
        allowFullScreen
        className="absolute inset-0 w-full h-full"
        loading="lazy"
      />
    </div>
  );
}
```

### Use Components in MDX

```mdx
---
// src/content/blog/getting-started.mdx
title: "Getting Started with Astro"
description: "Learn how to build fast websites with Astro"
pubDate: 2024-01-15
tags: ["astro", "tutorial"]
---

import { Callout } from '@/components/mdx/Callout';
import { YouTube } from '@/components/mdx/YouTube';
import Counter from '@/components/Counter';

# Getting Started with Astro

Welcome to this tutorial on building with Astro!

<Callout type="info" title="Prerequisites">
  Make sure you have Node.js 18+ or Bun installed before continuing.
</Callout>

## Installation

Run the following command to create a new project:

```bash
bun create astro@latest
```html

## Video Tutorial

<YouTube id="dsTXcSeAZq8" title="Astro Tutorial" />

## Interactive Example

Here's a counter component as a React island:

<Counter client:visible initial={5} />

<Callout type="warning">
  Remember to add `client:*` directives to make components interactive!
</Callout>

## Key Concepts

1. **Islands Architecture** — Ship zero JS by default
2. **Content Collections** — Type-safe content management
3. **Framework Agnostic** — Use React, Vue, Svelte, etc.

```

## SEO and Meta Tags

### BaseLayout with SEO

```astro
---
// src/layouts/BaseLayout.astro
import '@/styles/globals.css';

interface Props {
  title: string;
  description: string;
  ogImage?: string;
  canonicalUrl?: string;
  noindex?: boolean;
  jsonLd?: object;
}

const {
  title,
  description,
  ogImage = '/og-default.png',
  canonicalUrl,
  noindex = false,
  jsonLd,
} = Astro.props;

const siteTitle = 'My Site';
const fullTitle = `${title} | ${siteTitle}`;
const canonical = canonicalUrl || Astro.url.href;
const ogImageUrl = new URL(ogImage, Astro.site).href;
---

<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />

    <!-- Primary Meta Tags -->
    <title>{fullTitle}</title>
    <meta name="title" content={fullTitle} />
    <meta name="description" content={description} />
    <link rel="canonical" href={canonical} />

    <!-- Robots -->
    {noindex && <meta name="robots" content="noindex, nofollow" />}

    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="website" />
    <meta property="og:url" content={canonical} />
    <meta property="og:title" content={fullTitle} />
    <meta property="og:description" content={description} />
    <meta property="og:image" content={ogImageUrl} />
    <meta property="og:site_name" content={siteTitle} />

    <!-- Twitter -->
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:url" content={canonical} />
    <meta name="twitter:title" content={fullTitle} />
    <meta name="twitter:description" content={description} />
    <meta name="twitter:image" content={ogImageUrl} />

    <!-- Favicon -->
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <meta name="theme-color" content="#ffffff" />

    <!-- Preload critical fonts -->
    <link
      rel="preload"
      href="/fonts/inter-var.woff2"
      as="font"
      type="font/woff2"
      crossorigin
    />

    <!-- JSON-LD Structured Data -->
    {jsonLd && (
      <script type="application/ld+json" set:html={JSON.stringify(jsonLd)} />
    )}

    <!-- Default organization schema -->
    <script type="application/ld+json">
      {JSON.stringify({
        '@context': 'https://schema.org',
        '@type': 'Organization',
        name: siteTitle,
        url: Astro.site,
        logo: new URL('/logo.png', Astro.site).href,
      })}
    </script>
  </head>
  <body class="min-h-screen bg-background text-foreground antialiased">
    <slot />
  </body>
</html>
```

### Sitemap Configuration

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://example.com',
  integrations: [
    sitemap({
      filter: (page) => !page.includes('/admin/'),
      changefreq: 'weekly',
      priority: 0.7,
      lastmod: new Date(),
      // Custom entries
      customPages: [
        'https://example.com/external-page',
      ],
      serialize(item) {
        // Customize sitemap entries
        if (item.url.includes('/blog/')) {
          item.changefreq = 'monthly';
          item.priority = 0.8;
        }
        return item;
      },
    }),
  ],
});
```

## Partytown for Third-Party Scripts

### Configure Partytown

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import partytown from '@astrojs/partytown';

export default defineConfig({
  integrations: [
    partytown({
      config: {
        forward: ['dataLayer.push', 'gtag'], // Forward these functions
        debug: import.meta.env.DEV,
      },
    }),
  ],
});
```

### Use Partytown for Analytics

```astro
---
// src/layouts/BaseLayout.astro
---
<head>
  <!-- Google Analytics with Partytown -->
  <script type="text/partytown" src="https://www.googletagmanager.com/gtag/js?id=GA_ID"></script>
  <script type="text/partytown">
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'GA_ID');
  </script>

  <!-- Facebook Pixel with Partytown -->
  <script type="text/partytown">
    !function(f,b,e,v,n,t,s)
    {if(f.fbq)return;n=f.fbq=function(){n.callMethod?
    n.callMethod.apply(n,arguments):n.queue.push(arguments)};
    if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';
    n.queue=[];t=b.createElement(e);t.async=!0;
    t.src=v;s=b.getElementsByTagName(e)[0];
    s.parentNode.insertBefore(t,s)}(window, document,'script',
    'https://connect.facebook.net/en_US/fbevents.js');
    fbq('init', 'YOUR_PIXEL_ID');
    fbq('track', 'PageView');
  </script>
</head>
```

## SSR Configuration

### Enable SSR

```javascript
// astro.config.mjs
import { defineConfig } from 'astro/config';
import vercel from '@astrojs/vercel/serverless';
// or
import netlify from '@astrojs/netlify';
import cloudflare from '@astrojs/cloudflare';
import node from '@astrojs/node';

export default defineConfig({
  output: 'server', // or 'hybrid' for per-page control
  adapter: vercel(), // Choose your adapter
});
```

### Hybrid Rendering (Per-Page)

```javascript
// astro.config.mjs
export default defineConfig({
  output: 'hybrid', // Static by default, opt-in to SSR
  adapter: vercel(),
});
```

```astro
---
// src/pages/static-page.astro
// This page is static (default with hybrid)
---
<h1>I'm prerendered at build time</h1>
```

```astro
---
// src/pages/dynamic-page.astro
export const prerender = false; // Opt-in to SSR

// Access request data
const userAgent = Astro.request.headers.get('user-agent');
const ip = Astro.clientAddress;

// Dynamic data
const data = await fetch('https://api.example.com/data').then(r => r.json());
---
<h1>I'm rendered on each request</h1>
<p>Your IP: {ip}</p>
```

### API Endpoints

```typescript
// src/pages/api/contact.ts
import type { APIRoute } from 'astro';
import { z } from 'zod';

const contactSchema = z.object({
  name: z.string().min(2),
  email: z.string().email(),
  message: z.string().min(10),
});

export const POST: APIRoute = async ({ request }) => {
  try {
    const body = await request.json();
    const data = contactSchema.parse(body);

    // Send email, save to database, etc.
    await sendEmail(data);

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return new Response(JSON.stringify({ errors: error.issues }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
```

## Image Optimization

```astro
---
// src/pages/gallery.astro
import { Image, Picture } from 'astro:assets';
import heroImage from '../assets/hero.jpg';
---

<!-- Optimized image with automatic format conversion -->
<Image
  src={heroImage}
  alt="Hero image"
  width={1200}
  height={600}
  loading="eager"  <!-- Above the fold -->
  decoding="async"
/>

<!-- Responsive image with multiple formats -->
<Picture
  src={heroImage}
  formats={['avif', 'webp']}
  alt="Hero"
  widths={[400, 800, 1200]}
  sizes="(max-width: 640px) 400px, (max-width: 1024px) 800px, 1200px"
  loading="lazy"
/>

<!-- Remote images (must be in astro.config allowed domains) -->
<Image
  src="https://example.com/image.jpg"
  alt="Remote image"
  width={800}
  height={600}
  inferSize  <!-- Infer dimensions from remote -->
/>
```

## Testing Astro Sites

### E2E Testing with Playwright

```typescript
// tests/home.spec.ts
import { test, expect } from '@playwright/test';

test.describe('Homepage', () => {
  test('renders correctly', async ({ page }) => {
    await page.goto('/');

    // Check title
    await expect(page).toHaveTitle(/My Site/);

    // Check hero section
    const hero = page.locator('[data-testid="hero"]');
    await expect(hero).toBeVisible();

    // Check navigation
    const nav = page.getByRole('navigation');
    await expect(nav).toBeVisible();
  });

  test('hydrates islands correctly', async ({ page }) => {
    await page.goto('/');

    // Wait for counter island to hydrate
    const counter = page.locator('[data-testid="counter"]');
    await expect(counter).toBeVisible();

    // Test interaction
    await counter.getByRole('button', { name: /increase/i }).click();
    await expect(counter.getByText('1')).toBeVisible();
  });

  test('navigation works', async ({ page }) => {
    await page.goto('/');

    // Click blog link
    await page.getByRole('link', { name: /blog/i }).click();

    // Should navigate to blog page
    await expect(page).toHaveURL('/blog');
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Blog');
  });
});
```

### Build Output Validation

```typescript
// tests/build.spec.ts
import { test, expect } from '@playwright/test';
import { readdir, readFile } from 'fs/promises';
import { join } from 'path';

test.describe('Build output', () => {
  const distDir = './dist';

  test('generates sitemap', async () => {
    const sitemap = await readFile(join(distDir, 'sitemap-index.xml'), 'utf-8');
    expect(sitemap).toContain('sitemap');
  });

  test('generates robots.txt', async () => {
    const robots = await readFile(join(distDir, 'robots.txt'), 'utf-8');
    expect(robots).toContain('Sitemap:');
  });

  test('all pages have meta descriptions', async ({ page }) => {
    // Get all HTML files
    const pages = await getHtmlFiles(distDir);

    for (const pagePath of pages) {
      await page.goto(`file://${pagePath}`);
      const description = page.locator('meta[name="description"]');
      await expect(description).toHaveAttribute('content', /.+/);
    }
  });
});
```

## Performance Best Practices

1. **Static by default** — Use static generation unless you need SSR
1. **Lazy hydration** — Use `client:idle` or `client:visible` for non-critical
  islands
1. **Minimal islands** — Only hydrate what needs interactivity
1. **Image optimization** — Use `<Image>` and `<Picture>` components
1. **Font loading** — Preload critical fonts, use `font-display: swap`
1. **Third-party scripts** — Isolate with Partytown
1. **CSS optimization** — Tailwind JIT, purge unused styles

## Common Issues

| Issue | Solution |
|-------|----------|
| Island not hydrating | Check `client:*` directive is present |
| Content Collection type errors | Run `astro sync` to regenerate types |
| MDX components not working | Import with explicit path, check config |
| SSR adapter errors | Verify adapter compatibility with runtime |
| Image optimization slow | Use `sharp` for faster processing |
| Build output too large | Check for accidentally bundled files |
