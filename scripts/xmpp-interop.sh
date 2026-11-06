#!/usr/bin/env bash
# Interop check: built-in XMPP server (ADR-104) vs libstrophe (base of the devices' xmppc).
# Starts the `interop` example server (1 account, self-signed cert for xmpp.test), then runs
# tools/xmpp-interop/client.c in an Ubuntu container -> login with mandatory TLS, ping, answer a CR.
# libstrophe from the Ubuntu package, in the container only (not part of this repo).
# Needs Docker + network access for the container packages.
set -euo pipefail
cd "$(dirname "$0")/.."
PORT=${PORT:-15222}
WORK=$(mktemp -d)
trap 'kill "${SERVER:-0}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

cargo build -q -p dhonomos-xmpp --example interop
target/debug/examples/interop "$WORK" "$PORT" 2>"$WORK/server.log" &
SERVER=$!
for _ in $(seq 50); do grep -q listening "$WORK/server.log" && break; sleep 0.1; done
cp tools/xmpp-interop/client.c "$WORK/client.c"

# Container trusts the server cert like a device trusts a CA: via the system store.
# --network host -> server on 127.0.0.1; TLS name stays xmpp.test.
status=0
docker run --rm --network host -v "$WORK:/work" ubuntu:24.04 sh -ec '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq --no-install-recommends gcc libc6-dev libstrophe-dev ca-certificates >/dev/null
  cp /work/cert.pem /usr/local/share/ca-certificates/xmpp-test.crt
  update-ca-certificates >/dev/null
  gcc -o /tmp/client /work/client.c -lstrophe
  /tmp/client 127.0.0.1 '"$PORT"' dev-1@xmpp.test pw
' || status=$?
sleep 1
echo "--- server log"
cat "$WORK/server.log"
grep -q "connection request: Ok(Acknowledged)" "$WORK/server.log" || status=1
exit "$status"
