#!/usr/bin/env bash
# Release artifacts in dist/ (OP-09): container image (+ tarball), static x86_64 binary from it,
# CycloneDX SBOM, SHA-256 checksums. Signed if DHONOMOS_SIGNING_KEY names an SSH key
# (scripts/sign-release.sh). Tag + publish stay manual.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
if [ -n "$(git status --porcelain)" ]; then
  echo "the working tree is not clean" >&2
  exit 1
fi
scripts/check.sh
# Perf regression gate (OP-11). DHONOMOS_SKIP_BENCH=1 -> skip.
if [ -z "${DHONOMOS_SKIP_BENCH:-}" ]; then
  cargo xtask bench
fi
docker build -t "dhonomos:$version" .
rm -rf dist && mkdir -p dist
cid=$(docker create "dhonomos:$version")
docker cp "$cid:/dhonomos" "dist/dhonomos-$version-x86_64-linux-musl"
docker rm "$cid" >/dev/null
docker save "dhonomos:$version" | gzip > "dist/dhonomos-$version-image.tar.gz"
cargo xtask sbom --out "dist/dhonomos-$version.cdx.json"
(cd dist && sha256sum "dhonomos-$version"* > "SHA256SUMS-$version")
if [ -n "${DHONOMOS_SIGNING_KEY:-}" ]; then
  scripts/sign-release.sh "$DHONOMOS_SIGNING_KEY" "dist/SHA256SUMS-$version"
else
  echo "DHONOMOS_SIGNING_KEY not set: checksums are not signed" >&2
fi
echo "release $version ($(git rev-parse --short HEAD)):"
ls -l dist
