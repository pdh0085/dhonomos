#!/usr/bin/env bash
# Verify a downloaded release (OP-09): signature over the checksum file, then every listed
# artifact that is present.
#
#   scripts/verify-release.sh <allowed_signers> <dir> <version>
#
# <allowed_signers> line format: `release@dhonomos namespaces="dhonomos-release" ssh-ed25519 AAAA...`
# (see docs/guide/install.md).
set -euo pipefail
if [ $# -ne 3 ]; then
  echo "usage: $0 <allowed_signers> <dir> <version>" >&2
  exit 2
fi
signers=$(realpath "$1") dir=$2 version=$3
cd "$dir"
sums="SHA256SUMS-$version"
ssh-keygen -Y verify -f "$signers" -I release@dhonomos -n dhonomos-release -s "$sums.sig" < "$sums"
sha256sum --ignore-missing -c "$sums"
