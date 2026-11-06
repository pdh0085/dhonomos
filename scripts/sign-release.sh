#!/usr/bin/env bash
# Sign a release checksum file with an SSH key (OP-09): `ssh-keygen -Y sign` (OpenSSH)
# -> no extra tools to sign or verify. Signature covers every artifact via its SHA-256 line.
#
#   scripts/sign-release.sh <key> dist/SHA256SUMS-<version>   -> dist/SHA256SUMS-<version>.sig
#
# <key> = SSH private key (ed25519 recommended), or its public key with ssh-agent.
set -euo pipefail
if [ $# -ne 2 ]; then
  echo "usage: $0 <ssh-key> <SHA256SUMS file>" >&2
  exit 2
fi
key=$1 sums=$2
rm -f "$sums.sig"
ssh-keygen -q -Y sign -f "$key" -n dhonomos-release "$sums"
echo "signed: $sums.sig"
