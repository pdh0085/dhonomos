# Contributing

Thanks for your interest in Dhonomos.

## Ground rules

- **License**: contributions under Apache-2.0. Dependencies: MIT, Apache-2.0, BSD, ISC, Zlib or
  Unicode only; `cargo deny check` enforces it.
- **Clean room**: never read or copy GenieACS (AGPL) or other copyleft ACS/controller sources.
  Public docs + black-box observation are fine.
- **Specifications**: quote Broadband Forum specs as little as possible.
  Vendored BBF files keep their original headers (see `proto/README.md`, `schemas/README.md`).

## Development

```bash
rustup show                                         # installs the pinned toolchain
docker compose -f deploy/docker-compose.dev.yml up -d   # PostgreSQL, Mosquitto
cargo nextest run --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo deny check && cargo audit
# or all of the above at once:
scripts/check.sh
```

Operator UI (`ui/`, SvelteKit): built in a Node container by `scripts/build-ui.sh`
(`npm ci`, license allow-list, type check, lint, build -> `ui/build`).
Debug builds of `dhonomos` read `ui/build` from disk; release builds embed it -> build the UI first.
UI development: `npm run dev` in `ui/` against a local `dhonomos` (API proxied to :8080).
All UI text in English, in `ui/src/lib/messages.ts`.

DB queries are checked at compile time. Builds use the offline data in `.sqlx/`. After a query or
migration change, start the dev stack and run:

```bash
export DATABASE_URL=postgres://dhonomos:dhonomos@127.0.0.1:5432/dhonomos
sqlx migrate run --source crates/store/migrations
cargo sqlx prepare --workspace   # commit .sqlx/
```

Store integration tests start their own PostgreSQL container (Docker needed).

Fuzzing (nightly toolchain + `cargo install cargo-fuzz`): `scripts/fuzz.sh [seconds]` runs all
targets in `fuzz/fuzz_targets/` in parallel.

Local server: `cargo run -p dhonomos -- --database-url postgres://dhonomos:dhonomos@127.0.0.1:5432/dhonomos --acs-plaintext --cpe-auth none --require-admin-totp false`.
Admins need two-factor auth by default, which needs `--secrets-key`; to try it, pass a key instead
of `--require-admin-totp false`.
Without `--acs-plaintext` the ACS needs `--acs-tls-cert` + `--acs-tls-key` (PEM).

Optional peers: `--profile usp` (OB-USP-Agent), `--profile cwmp` (CWMP CPE simulator).

## Code comments

Engineer's memo style: short fragments, `->` for "gives / then / so", one idea per line.
Keep the why, requirement/ADR IDs and security rules; drop comments that only repeat the code.

```rust
//! SSE (NB-03): `GET /api/v1/stream` -> alarm changes.
//! Poll DB 1/s per connection -> works for a change from any process.
```

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/): `feat(cwmp): ...`, `fix(usp-mtp): ...`, `docs: ...`.
- Code, comments and commit messages in English. Design docs under `docs/`: Korean, English
  technical terms.
- Bigger design changes -> open an issue first.
