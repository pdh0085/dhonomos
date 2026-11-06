#!/usr/bin/env bash
# NAT live test (CW-08, Phase 4 DoD): CPE behind real NAT gets UDP CRs via built-in STUN server.
#
#   WAN 172.31.10.0/24: dhonomos (.2) - router (.254, MASQUERADE)
#   LAN 172.31.20.0/24 (internal): router (.254) - CPE (.10, default route via router)
#
# CPE reports a private ConnectionRequestURL -> dhonomos must use STUN + UDP.
# Needs: dev DB (dhonomos-dev) + alpine image.
# Debug binaries run in alpine, host glibc mounted read-only. Router: iptables from Alpine repo.
set -euo pipefail
cd "$(dirname "$0")/.."
P=dhonomos-nat
DB_NET=${DB_NET:-dhonomos-dev_dhonomos}
DB_URL=${DB_URL:-postgres://dhonomos:dhonomos@postgres:5432/dhonomos}
ROUNDS=${ROUNDS:-3}
SERIAL="NAT$(date +%s)"
LIBS=(-v /lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:ro -v /lib64:/lib64:ro)
LD=/lib64/ld-linux-x86-64.so.2
API=http://172.31.10.2:8080/api/v1

cleanup() {
  docker rm -f "$P-router" "$P-acs" "$P-cpe-host" "$P-cpe" >/dev/null 2>&1 || true
  docker network rm "$P-wan" "$P-lan" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

cargo build -q -p dhonomos -p dhonomos-simulator --bin dhonomos --bin nat-cpe
docker network create --subnet 172.31.10.0/24 "$P-wan" >/dev/null
docker network create --internal --subnet 172.31.20.0/24 "$P-lan" >/dev/null

echo "== router"
docker run -d --name "$P-router" --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1 \
  --network "$P-wan" --ip 172.31.10.254 alpine sleep infinity >/dev/null
docker network connect --ip 172.31.20.254 "$P-lan" "$P-router"
docker exec "$P-router" sh -ec '
  apk add -q iptables
  iptables -t nat -A POSTROUTING -s 172.31.20.0/24 ! -d 172.31.20.0/24 -j MASQUERADE --random'

echo "== dhonomos"
docker create --name "$P-acs" --network "$P-wan" --ip 172.31.10.2 "${LIBS[@]}" \
  -v "$PWD/target/debug/dhonomos:/dhonomos:ro" alpine "$LD" /dhonomos \
  --database-url "$DB_URL" --acs-plaintext --cpe-auth none \
  --acs-listen 0.0.0.0:7547 --api-listen 0.0.0.0:8080 \
  --files-dir /tmp/files --files-listen 0.0.0.0:7548 --files-public-url http://172.31.10.2:7548 \
  --files-secret "$(head -c32 /dev/urandom | base64)" --secrets-key "$(head -c32 /dev/urandom | base64)" \
  --stun-listen 0.0.0.0:3478 --stun-public-address 172.31.10.2:3478 >/dev/null
docker network connect "$DB_NET" "$P-acs"
docker start "$P-acs" >/dev/null
for _ in $(seq 60); do curl -sf http://172.31.10.2:8080/healthz >/dev/null && break; sleep 1; done

echo "== CPE behind NAT"
docker run -d --name "$P-cpe-host" --cap-add NET_ADMIN --network "$P-lan" --ip 172.31.20.10 \
  alpine sleep infinity >/dev/null
docker exec "$P-cpe-host" ip route replace default via 172.31.20.254
docker run -d --name "$P-cpe" --network "container:$P-cpe-host" "${LIBS[@]}" \
  -v "$PWD/target/debug/nat-cpe:/nat-cpe:ro" alpine "$LD" /nat-cpe \
  --acs 172.31.10.2:7547 --serial "$SERIAL" --expect "$((ROUNDS + 1))" --stun-interval 5 --timeout 240 >/dev/null

device=""
for _ in $(seq 60); do
  device=$(curl -sf "$API/devices?q=$SERIAL" | python3 -c 'import sys,json; i=json.load(sys.stdin)["items"]; print(i[0]["id"] if i else "")')
  [ -n "$device" ] && break
  sleep 1
done
[ -n "$device" ] || { docker logs "$P-cpe"; echo "the CPE never registered" >&2; exit 1; }
seen_from=$(curl -sf "$API/devices/$device" | python3 -c 'import sys,json; print(json.load(sys.stdin)["last_remote_addr"])')
echo "device $device registered; the ACS sees it from $seen_from (the router's WAN address)"

echo "== queue a task and wake it, $ROUNDS times"
# Before first STUN binding -> no UDP address for CR.
for _ in $(seq 30); do
  outcome=$(curl -sf -XPOST "$API/devices/$device/connection-request" | python3 -c 'import sys,json; print(json.load(sys.stdin)["connection_request"])')
  case "$outcome" in sent\ over\ UDP*) break ;; esac
  sleep 2
done
sleep 5
tasks=()
for i in $(seq "$ROUNDS"); do
  resp=$(curl -sf -XPOST "$API/devices/$device/tasks" -H 'content-type: application/json' \
    -d '{"kind":"get_parameter_values","payload":{"names":["Device.DeviceInfo.UpTime"]},"connection_request":true}')
  tasks+=("$(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["id"])')")
  echo "round $i: $(echo "$resp" | python3 -c 'import sys,json; print(json.load(sys.stdin)["connection_request"])')"
  sleep 8     # session, then next STUN keepalive
done

status=0
for _ in $(seq 60); do
  [ "$(docker inspect -f '{{.State.Running}}' "$P-cpe")" = false ] && break
  sleep 1
done
docker logs "$P-cpe"
[ "$(docker inspect -f '{{.State.ExitCode}}' "$P-cpe")" = 0 ] || status=1
for t in "${tasks[@]}"; do
  state=$(curl -sf "$API/tasks/$t" | python3 -c 'import sys,json; print(json.load(sys.stdin)["state"])')
  echo "task $t: $state"
  [ "$state" = succeeded ] || status=1
done
curl -sf -XDELETE "$API/devices/$device" >/dev/null || true
[ $status = 0 ] && echo "NAT test passed" || { docker logs --tail 30 "$P-acs"; echo "NAT test FAILED" >&2; }
exit $status
