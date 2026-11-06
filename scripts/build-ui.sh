#!/usr/bin/env bash
# Build operator UI (ui/build) in a Node container -> no host Node needed.
# Release build of `dhonomos` embeds ui/build; debug build reads it from disk at runtime.
#
# License policy (CONTRIBUTING.md) covers build tools too: never install GPL/AGPL/LGPL/MPL/EUPL/SSPL
# packages, even if not in the bundle (ADR-029).
set -euo pipefail
cd "$(dirname "$0")/.."
# Local settings (not in git), e.g. DHONOMOS_WORK_DIR=/data/dhonomos-work
# -> generated files (node_modules, .svelte-kit, build) in $DHONOMOS_WORK_DIR/ui,
#    workspace = sources only.
# -> ui/build = link to the output (embedded by `dhonomos`).
[ -f .env.local ] && . ./.env.local
UI="$PWD/ui"
if [ -n "${DHONOMOS_WORK_DIR:-}" ]; then
  UI="$DHONOMOS_WORK_DIR/ui"
  mkdir -p "$UI"
  rsync -a --delete --exclude /node_modules --exclude /.svelte-kit --exclude /build ui/ "$UI/"
fi
ALLOWED="MIT;ISC;BSD-2-Clause;BSD-3-Clause;Apache-2.0;0BSD;CC0-1.0;CC-BY-4.0;BlueOak-1.0.0;Python-2.0;Unlicense"
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
  -v "$UI:/w" -w /w node:22-alpine sh -ec "
    # npm 10 (bundled with Node 22) rejects valid lockfiles with optional peers; use npm 11
    # (the version of the Dockerfile; exact, so that a new release cannot change the build).
    npx -y npm@11.21.0 ci --no-audit --no-fund
    npx -y license-checker-rseidelsohn@4.4.2 --excludePrivatePackages --onlyAllow '$ALLOWED' --summary
    npm run check
    npm run lint
    npm run build"
if [ "$UI" != "$PWD/ui" ]; then
  [ -L ui/build ] || rm -rf ui/build
  ln -sfn "$UI/build" ui/build
fi
