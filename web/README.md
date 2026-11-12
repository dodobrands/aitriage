# AITriage Web Dashboard

Browser-based security dashboard for AITriage. It talks to the Go backend's REST API
(`/api/*`) served by `aitriage web`, and is embedded into the Go binary at build time.

## Tech Stack

| Concern | Choice |
| :--- | :--- |
| Framework | React 19 |
| Language | TypeScript |
| Bundler | Vite 8 |
| Styling | TailwindCSS 4 (`@tailwindcss/vite`) |
| Routing | `react-router-dom` 7 |
| State | `zustand` |
| Data fetching | `axios` and `fetch` |
| i18n | `i18next` / `react-i18next` (English + Russian) |
| Icons | Material Symbols (Google Fonts) |
| Markdown | `react-markdown`, `react-syntax-highlighter` |
| Animation | `framer-motion` |
| Visualization | `react-force-graph-2d` |
| Tests | Vitest |

## Local Development

```bash
npm ci
npm run dev        # Vite dev server on http://localhost:5173
```

The dev server proxies `/api` to the backend on `http://localhost:8080`
(see `vite.config.ts`). For a full local stack, run a backend there in a
separate terminal: `aitriage web` serves the backend from the scanner image,
while `./bin/aitriage web --runtime native`, run from the repository root after
`make build`, serves the backend from your checkout.

## Scripts

```bash
npm run dev        # Start Vite dev server with HMR
npm run build      # Type-check (tsc -b) + production build to dist/
npm run preview    # Preview the production build locally
npm run lint       # Run ESLint
npm run format     # Prettier + eslint --fix
npm test           # Run the Vitest unit tests once
npm run test:watch # Run Vitest in watch mode
```

## How It Ships

The production build is compiled into the Go binary rather than served separately.
From the repository root:

```bash
make sync-web      # npm ci + npm run build, then copy web/dist → internal/server/ui/dist
make build         # Build the Go binary with embedded assets
```

The Docker image builds the frontend itself (see the root `Dockerfile`), so
`make up` and `make docker-build` need no `sync-web`. A standalone Nginx
deployment is also available via `web/Dockerfile` and `web/nginx.conf`, which
proxies `/api/` to a `backend` service.

## Project Layout

```
web/src/
├── pages/         # Route-level views
├── components/    # Reusable UI components
├── ui/            # Low-level primitives
├── hooks/         # Custom React hooks
├── services/      # API clients
├── store/         # Zustand state stores
├── lib/           # Pure helpers and their Vitest tests
├── locales/       # i18n resources (en, ru)
├── types/         # Shared TypeScript types (per feature)
├── types.ts       # Shared TypeScript types
├── i18n.ts        # i18next configuration
└── main.tsx       # App entry point
```

## Internationalization

Translations live in `src/locales/<lang>/{translation,pages,components}.json`.
The language is auto-detected in the browser with a fallback to English
(`src/i18n.ts`). To add a language, create a new locale directory and register it
in `i18n.ts`.
