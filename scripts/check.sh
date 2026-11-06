#!/usr/bin/env bash
# Same checks as .github/workflows/ci.yml, locally.
# Run before every commit until a Gitea Actions runner exists (ADR-024).
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step fmt;     cargo fmt --all --check
step clippy;  cargo clippy --workspace --all-targets --locked -- -D warnings
step nextest; cargo nextest run --workspace --locked --no-tests=pass
step deny;    cargo deny check
step audit;   cargo audit
if [[ "${1:-}" == "--msrv" ]]; then
  step msrv;  cargo +1.96 check --workspace --locked
fi
printf '\nAll checks passed.\n'
