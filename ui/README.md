# Dhonomos operator UI

SvelteKit 2 single-page app (Svelte 5 runes, Tailwind CSS 3). Served by the `dhonomos` API
listener, embedded in release builds.

- Build: `scripts/build-ui.sh` from the repo root (Node container: `npm ci` with npm 11,
  license allow-list check, `svelte-check`, Prettier, `vite build` -> `ui/build`).
- Develop: run `dhonomos` locally, then `npm run dev` here; `/api` proxied to `127.0.0.1:8080`.
- Text: all user-facing strings in English, in `src/lib/messages.ts` (ADR-025).
- Dependencies: permissive licenses only, build tools included (ADR-029). No Vite 8 / Tailwind 4:
  they need `lightningcss` (MPL-2.0).
