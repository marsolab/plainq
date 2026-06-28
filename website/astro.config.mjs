// @ts-check
import { defineConfig } from "astro/config";
import react from "@astrojs/react";
import starlight from "@astrojs/starlight";
import tailwindcss from "@tailwindcss/vite";

// https://astro.build/config
export default defineConfig({
  site: "https://plainq.dev",
  integrations: [
    react(),
    starlight({
      title: "PlainQ Docs",
      description:
        "Documentation for PlainQ — the truly simple queue service. One binary, gRPC API, CLI, TUI, and a built-in admin UI.",
      logo: {
        light: "./src/assets/logo-light.svg",
        dark: "./src/assets/logo-dark.svg",
        replacesTitle: true,
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/marsolab/plainq",
        },
      ],
      customCss: ["./src/styles/starlight.css"],
      // Mount docs under /docs (content lives in src/content/docs/docs/**).
      sidebar: [
        {
          label: "Getting started",
          items: [{ autogenerate: { directory: "docs/getting-started" } }],
        },
        {
          label: "Guides",
          items: [{ autogenerate: { directory: "docs/guides" } }],
        },
        {
          label: "Reference",
          items: [{ autogenerate: { directory: "docs/reference" } }],
        },
      ],
    }),
  ],
  vite: {
    plugins: [tailwindcss()],
  },
});
