#!/usr/bin/env bash
# WireGuard hub e2e test (ADR-110, stage 2): dhonomos-wg-hub in a privileged container
# applies the state of a real Dhonomos server to the kernel -> members of 2 networks reach
# each other, their sites + the hub only as the overlay allows.
#
#   dhonomos-wge2e-net 172.31.30.0/24:
#     db (.2, postgres) - acs (.3, dhonomos, API :8080)
#     hub (.10, dhonomos-wg-hub; dwg51820 = N1 10.77.0.0/24, dwg51821 = N2 10.77.1.0/24)
#     a (.21, N1 device, LAN 192.168.10.0/24)   b (.22, N1 device, LAN 192.168.20.0/24)
#     c (.23, N1 client)                        d (.24, N2 device, LAN 192.168.10.0/24)
#
# Every member dials only the hub. d's LAN = a's LAN (isolation by per-network routing tables).
# d routes all of 10.77.0.0/16 into its tunnel -> hub must drop d's packets to N1.
# Needs: Docker with privileged containers, host wireguard kernel module, alpine +
# postgres:17-alpine images, Alpine package repo (nftables, iproute2, wireguard-tools).
# Debug binaries run in alpine with host glibc mounted read-only.
# Own DB; touches only dhonomos-wge2e-* containers + dhonomos-wge2e-net. Not part of check.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
P=dhonomos-wge2e
NET=$P-net
SUBNET=172.31.30.0/24
LIBS=(-v /lib/x86_64-linux-gnu:/lib/x86_64-linux-gnu:ro -v /lib64:/lib64:ro)
LD=/lib64/ld-linux-x86-64.so.2
API=http://172.31.30.3:8080/api/v1
HUB=$P-hub
HUB_ARGS=(--server http://172.31.30.3:8080 --allow-http --token-file /run/wge2e/token
  --key-file /run/wge2e/private.key --resync-interval 10 --status-interval 5 --wait 25)
TMP=""

cleanup() {
  docker rm -f "$P-a" "$P-b" "$P-c" "$P-d" "$HUB" "$P-acs" "$P-db" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  [ -z "$TMP" ] || rm -rf "$TMP"
}
trap cleanup EXIT
cleanup

ok() { echo "ok - $*"; }

fail() {
  echo "FAIL - $*"
  echo "== server log (last 60 lines)"
  docker logs --tail 60 "$P-acs" 2>&1 || true
  echo "== hub log"
  docker exec "$HUB" cat /run/wge2e/hub.log 2>&1 || true
  docker logs "$HUB" 2>&1 || true
  for cmd in "wg show" "ip rule" "ip route show table all" "nft list ruleset"; do
    echo "== hub: $cmd"
    # shellcheck disable=SC2086
    docker exec "$HUB" $cmd 2>&1 || true
  done
  exit 1
}

now_ms() { echo $(($(date +%s%N) / 1000000)); }

# wait_for <seconds> <what> <command...>: poll until success; print the time taken.
wait_for() {
  local timeout=$1 what=$2
  shift 2
  local start
  start=$(now_ms)
  while :; do
    if "$@" >/dev/null 2>&1; then
      ok "$what ($(($(now_ms) - start)) ms)"
      return 0
    fi
    [ $(($(now_ms) - start)) -lt $((timeout * 1000)) ] || fail "$what (not within ${timeout} s)"
    sleep 0.2
  done
}

# check <what> <command...>: command must succeed now.
check() {
  local what=$1
  shift
  "$@" >/dev/null 2>&1 && ok "$what" || fail "$what"
}

# api <method> <path> [json]: API call with admin token (from a file, never on a command line).
# Prints the body; error status -> fail.
api() {
  local args=(-sS --fail-with-body -X "$1" -H @"$TMP/auth" "$API$2")
  [ $# -lt 3 ] || args+=(-H 'content-type: application/json' --data-binary "$3")
  curl "${args[@]}"
}

hub() { docker exec "$HUB" "$@"; }
in_c() { local c=$1; shift; docker exec "$P-$c" "$@"; }
ping_ok() { in_c "$1" ping -c1 -W1 "${@:2}"; }
ping_fails() { ! in_c "$1" ping -c2 -W1 "${@:2}"; }

# Hub runs in the background of its container; run-hub records its pid + exit code.
install_hub_runner() {
  docker exec -i "$HUB" sh -c 'cat >/run/wge2e/run-hub' <<EOF
rm -f /run/wge2e/hub.exit
$LD /dhonomos-wg-hub ${HUB_ARGS[*]} >>/run/wge2e/hub.log 2>&1 &
echo \$! >/run/wge2e/hub.pid
wait \$!
echo \$? >/run/wge2e/hub.exit
EOF
}

start_hub() {
  hub rm -f /run/wge2e/hub.exit /run/wge2e/hub.pid
  docker exec -d "$HUB" sh /run/wge2e/run-hub
  for _ in $(seq 50); do
    hub test -s /run/wge2e/hub.pid && return 0
    sleep 0.1
  done
  fail "the hub process starts"
}

stop_hub() {
  hub sh -c 'kill -TERM "$(cat /run/wge2e/hub.pid)"'
  for _ in $(seq 50); do
    hub test -s /run/wge2e/hub.exit && break
    sleep 0.2
  done
  [ "$(hub cat /run/wge2e/hub.exit 2>/dev/null)" = 0 ] || fail "the hub exits 0 on SIGTERM"
  ok "the hub exits 0 on SIGTERM"
}

dry_run() { hub "$LD" /dhonomos-wg-hub "${HUB_ARGS[@]}" --dry-run 2>/dev/null; }

if docker network ls -q | xargs -r docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' |
  tr ' ' '\n' | grep -qx "$SUBNET"; then
  echo "$SUBNET is in use by another Docker network" >&2
  exit 1
fi

TMP=$(mktemp -d)
chmod 700 "$TMP"
cargo build -q -p dhonomos -p dhonomos-wg-hub
API_TOKEN=$(head -c 32 /dev/urandom | base64 | tr -d '/+=')
printf 'Authorization: Bearer %s\n' "$API_TOKEN" >"$TMP/auth"
DB_PASSWORD=$(head -c 16 /dev/urandom | base64 | tr -d '/+=')
cat >"$TMP/acs.env" <<EOF
DHONOMOS_DATABASE_URL=postgres://dhonomos:$DB_PASSWORD@172.31.30.2:5432/dhonomos
DHONOMOS_API_TOKEN=$API_TOKEN
DHONOMOS_SECRETS_KEY=$(head -c 32 /dev/urandom | base64)
DHONOMOS_FILES_SECRET=$(head -c 32 /dev/urandom | base64)
EOF
printf 'POSTGRES_USER=dhonomos\nPOSTGRES_DB=dhonomos\nPOSTGRES_PASSWORD=%s\n' "$DB_PASSWORD" >"$TMP/db.env"
unset API_TOKEN DB_PASSWORD

echo "== database and server"
docker network create --subnet "$SUBNET" "$NET" >/dev/null
docker run -d --name "$P-db" --network "$NET" --ip 172.31.30.2 --env-file "$TMP/db.env" \
  postgres:17-alpine >/dev/null
for _ in $(seq 60); do
  docker exec "$P-db" pg_isready -q -h 172.31.30.2 -U dhonomos && break
  sleep 1
done
docker run -d --name "$P-acs" --network "$NET" --ip 172.31.30.3 --env-file "$TMP/acs.env" "${LIBS[@]}" \
  -v "$PWD/target/debug/dhonomos:/dhonomos:ro" alpine "$LD" /dhonomos \
  --acs-plaintext --cpe-auth none --acs-listen 0.0.0.0:7547 --api-listen 0.0.0.0:8080 \
  --files-dir /tmp/files >/dev/null
wait_for 60 "the server answers /healthz" curl -sf http://172.31.30.3:8080/healthz

psql() { docker exec "$P-db" psql -q -v ON_ERROR_STOP=1 -U dhonomos -d dhonomos -c "$1" >/dev/null; }

echo "== server data"
HUB_ID=$(api POST /wireguard/hubs '{"name":"e2e-hub","endpoint_host":"172.31.30.10"}' | jq -r .id)
api POST "/wireguard/hubs/$HUB_ID/token" | jq -r .token >"$TMP/hub.token"
N1_JSON=$(api POST /wireguard/networks "{\"hub_id\":\"$HUB_ID\",\"name\":\"n1\"}")
N2_JSON=$(api POST /wireguard/networks "{\"hub_id\":\"$HUB_ID\",\"name\":\"n2\"}")
N1=$(jq -r .id <<<"$N1_JSON")
N2=$(jq -r .id <<<"$N2_JSON")
[ "$(jq -r '.ipv4_prefix + " " + (.listen_port|tostring)' <<<"$N1_JSON")" = "10.77.0.0/24 51820" ] ||
  fail "N1 is 10.77.0.0/24 on 51820: $N1_JSON"
[ "$(jq -r '.ipv4_prefix + " " + (.listen_port|tostring)' <<<"$N2_JSON")" = "10.77.1.0/24 51821" ] ||
  fail "N2 is 10.77.1.0/24 on 51821: $N2_JSON"
ok "networks N1 10.77.0.0/24 on 51820 and N2 10.77.1.0/24 on 51821"

device() { api POST /devices "{\"oui\":\"00E0FC\",\"product_class\":\"E2E\",\"serial_number\":\"WGE2E-$1\"}" | jq -r .id; }
device_member() { # <network> <device> <site prefix> -> member JSON
  api POST "/wireguard/networks/$1/members" \
    "{\"kind\":\"device\",\"device_id\":\"$2\",\"site_prefixes\":[{\"prefix\":\"$3\"}]}"
}
DEV_A=$(device A)
DEV_B=$(device B)
DEV_D=$(device D)
A_JSON=$(device_member "$N1" "$DEV_A" 192.168.10.0/24)
B_JSON=$(device_member "$N1" "$DEV_B" 192.168.20.0/24)
D_JSON=$(device_member "$N2" "$DEV_D" 192.168.10.0/24)
# c brings its own key pair: server makes one only after the hub has reported its key.
C_KEY=$(docker run --rm alpine sh -c 'apk add -q wireguard-tools >/dev/null; k=$(wg genkey); echo "$k $(echo "$k" | wg pubkey)"')
api POST "/wireguard/networks/$N1/members" "{\"kind\":\"client\",\"name\":\"c\",\"user_id\":null,\"public_key\":\"${C_KEY#* }\"}" | jq --arg k "${C_KEY%% *}" '.private_key = $k' >"$TMP/c.json"
MA=$(jq -r .id <<<"$A_JSON")
MB=$(jq -r .id <<<"$B_JSON")
MD=$(jq -r .id <<<"$D_JSON")
ADDR_A=$(jq -r .address <<<"$A_JSON")
ADDR_B=$(jq -r .address <<<"$B_JSON")
ADDR_D=$(jq -r .address <<<"$D_JSON")
ADDR_C=$(jq -r .address "$TMP/c.json")
MC=$(jq -r .id "$TMP/c.json")
jq -r .private_key "$TMP/c.json" >"$TMP/c.key"
rm "$TMP/c.json"
echo "members: a $ADDR_A, b $ADDR_B, c $ADDR_C (N1); d $ADDR_D (N2)"

echo "== member containers"
for m in a:21 b:22 c:23 d:24; do
  docker run -d --name "$P-${m%%:*}" --cap-add NET_ADMIN --network "$NET" --ip "172.31.30.${m##*:}" \
    alpine sleep infinity >/dev/null
done
for m in a b c d; do
  in_c "$m" apk add -q wireguard-tools iproute2 >/dev/null
done
docker exec -i "$P-c" sh -c 'umask 077; cat >/k' <"$TMP/c.key"
for m in a b d; do
  in_c "$m" sh -c 'umask 077; wg genkey >/k'
done
for m in A:a:$MA B:b:$MB D:d:$MD; do
  IFS=: read -r _ c id <<<"$m"
  psql "UPDATE wg_members SET public_key = '$(in_c "$c" sh -c 'wg pubkey </k')' WHERE id = '$id'"
done
ok "device member keys set in the database"

echo "== hub"
docker run -d --name "$HUB" --privileged --network "$NET" --ip 172.31.30.10 "${LIBS[@]}" \
  -v "$PWD/target/debug/dhonomos-wg-hub:/dhonomos-wg-hub:ro" alpine sleep infinity >/dev/null
hub apk add -q nftables iproute2 wireguard-tools >/dev/null
hub sh -ec '
  sysctl -q -w net.ipv4.ip_forward=1
  sysctl -q -w net.ipv4.conf.all.rp_filter=1
  nft add table inet e2e_foreign
  ip link add wg0 type wireguard
  mkdir -p /run/wge2e
  chmod 700 /run/wge2e'
docker exec -i "$HUB" sh -c 'umask 077; cat >/run/wge2e/token' <"$TMP/hub.token"
FOREIGN_NFT=$(hub nft list table inet e2e_foreign)
install_hub_runner
foreign_untouched() {
  hub ip link show wg0 >/dev/null &&
    [ "$(hub wg show wg0 listen-port)" = 0 ] &&
    [ "$(hub wg show wg0 private-key)" = "(none)" ] &&
    [ "$(hub nft list table inet e2e_foreign)" = "$FOREIGN_NFT" ]
}
start_hub

# 1.
hub_key() { api GET "/wireguard/hubs/$HUB_ID" | jq -er '.public_key // empty'; }
wait_for 10 "the hub's public key reaches the server" hub_key
HUB_PUB=$(hub_key)

# Members: hub = only peer.
wg_member() { # <container> <address/len> <port> <allowed IPs> [lan address/len]
  local c=$1 addr=$2 port=$3 allowed=$4 lan=${5:-}
  in_c "$c" sh -ec "
    ip link add wg0 type wireguard
    wg set wg0 private-key /k peer '$HUB_PUB' endpoint 172.31.30.10:$port persistent-keepalive 5 allowed-ips '$allowed'
    ip addr add $addr dev wg0
    ip link set wg0 up
    for p in \$(echo '$allowed' | tr , ' '); do ip route replace \$p dev wg0; done
    if [ -n '$lan' ]; then ip link add lan0 type dummy; ip addr add $lan dev lan0; ip link set lan0 up; fi"
}
wg_member a "$ADDR_A/24" 51820 10.77.0.0/24,192.168.20.0/24 192.168.10.1/24
wg_member b "$ADDR_B/24" 51820 10.77.0.0/24,192.168.10.0/24 192.168.20.1/24
wg_member c "$ADDR_C/24" 51820 10.77.0.0/24,192.168.10.0/24,192.168.20.0/24
wg_member d "$ADDR_D/24" 51821 10.77.0.0/16 192.168.10.1/24

# 2.
peers_are() { [ "$(hub wg show "$1" peers | wc -l)" = "$2" ]; }
has_peer() { hub wg show "$1" peers | grep -qxF "$2"; }
has_address() { hub ip -4 -o addr show dev "$1" | grep -q "inet $2 "; }
listens() { [ "$(hub wg show "$1" listen-port)" = "$2" ]; }
loose() { [ "$(hub cat "/proc/sys/net/ipv4/conf/$1/rp_filter")" = 2 ]; }
has_rule() { hub ip rule | grep -qxF "10000:	from all iif $1 lookup $2"; }
no_rule() { ! hub ip rule | grep -qF "iif $1 "; }
table() { hub ip route show table "$1" 2>/dev/null | sed 's/ *$//'; }
table_is() { [ "$(table "$1" | sort)" = "$(sort <<<"$2")" ]; }
has_route() { table "$1" | grep -q "^$2 "; }
link_gone() { ! hub ip link show "$1" >/dev/null 2>&1; }
both_peered() { peers_are dwg51820 3 && peers_are dwg51821 1; }

wait_for 10 "dwg51820 has its 3 peers and dwg51821 its 1" both_peered
check "dwg51820 has 10.77.0.1/24" has_address dwg51820 10.77.0.1/24
check "dwg51821 has 10.77.1.1/24" has_address dwg51821 10.77.1.1/24
check "dwg51820 listens on 51820" listens dwg51820 51820
check "dwg51821 listens on 51821" listens dwg51821 51821
both_loose() { loose dwg51820 && loose dwg51821; }
check "rp_filter is loose (2) on dwg51820 and dwg51821" both_loose
check "rule iif dwg51820 lookup 151820 at priority 10000" has_rule dwg51820 151820
check "rule iif dwg51821 lookup 151821 at priority 10000" has_rule dwg51821 151821
T1="10.77.0.0/24 dev dwg51820 proto static scope link src 10.77.0.1
192.168.10.0/24 dev dwg51820 proto static scope link
192.168.20.0/24 dev dwg51820 proto static scope link
unreachable default proto static"
T2="10.77.1.0/24 dev dwg51821 proto static scope link src 10.77.1.1
192.168.10.0/24 dev dwg51821 proto static scope link
unreachable default proto static"
check "table 151820: tunnel prefix, 192.168.10.0/24, 192.168.20.0/24, unreachable default" table_is 151820 "$T1"
check "table 151821: tunnel prefix, 192.168.10.0/24, unreachable default" table_is 151821 "$T2"
check "the firewall table inet dhonomos_wg exists" hub nft list table inet dhonomos_wg
check "wg0 and table inet e2e_foreign are untouched" foreign_untouched

# 3.
wait_for 15 "a reaches the hub (10.77.0.1)" ping_ok a 10.77.0.1
wait_for 10 "a reaches b's tunnel address" ping_ok a "$ADDR_B"
wait_for 10 "a's site reaches b's site (192.168.10.1 -> 192.168.20.1)" ping_ok a -I 192.168.10.1 192.168.20.1
wait_for 10 "c reaches a's site (192.168.10.1)" ping_ok c 192.168.10.1
wait_for 10 "c reaches b's site (192.168.20.1)" ping_ok c 192.168.20.1
wait_for 15 "d reaches its hub address (10.77.1.1)" ping_ok d 10.77.1.1
check "d cannot reach a's tunnel address (another network)" ping_fails d "$ADDR_A"
check "d cannot reach N1's hub address 10.77.0.1" ping_fails d 10.77.0.1

# 4.
handshake_seen() {
  api GET "/wireguard/members/$MA" | jq -e '.hub_status.latest_handshake != null and .hub_status.rx_bytes > 0'
}
wait_for 20 "member a's hub_status shows a handshake and received bytes" handshake_seen
hub_seen() { api GET "/wireguard/hubs/$HUB_ID" | jq -e '.last_seen_at != null and .version != null'; }
check "the hub record shows last_seen_at and version" hub_seen

# 5.
api PATCH "/wireguard/members/$MA" \
  '{"site_prefixes":[{"prefix":"192.168.10.0/24"},{"prefix":"192.168.11.0/24"}]}' >/dev/null
wait_for 5 "a new site prefix of a reaches table 151820 (long-poll)" has_route 151820 192.168.11.0/24

# 5b. PSK for c: made by server -> taken by hub -> used by c.
api PATCH "/wireguard/members/$MC" '{"preshared_key_enabled":true}' | jq -r .preshared_key >"$TMP/c.psk"
docker exec -i "$P-c" sh -c 'umask 077; cat >/psk' <"$TMP/c.psk"
rm "$TMP/c.psk"
PUB_C=$(in_c c sh -c 'wg pubkey </k')
c_psk_on_hub() {
  [ "$(hub wg show dwg51820 preshared-keys | awk -v k="$PUB_C" '$1 == k { print $2 }')" = "$(in_c c cat /psk)" ]
}
wait_for 5 "the hub takes c's pre-shared key (long-poll)" c_psk_on_hub
in_c c wg set wg0 peer "$HUB_PUB" preshared-key /psk
wait_for 10 "c reaches a's site with the pre-shared key" ping_ok c 192.168.10.1
api PATCH "/wireguard/members/$MC" '{"preshared_key_enabled":false}' >/dev/null
c_psk_cleared() { hub wg show dwg51820 preshared-keys | grep -qxF "$PUB_C	(none)"; }
wait_for 5 "the hub clears c's pre-shared key once it is turned off" c_psk_cleared
in_c c wg set wg0 peer "$HUB_PUB" preshared-key /dev/null

# 6.
PUB_B=$(in_c b sh -c 'wg pubkey </k')
api POST "/wireguard/members/$MB/revoke" '{"reason":"e2e"}' >/dev/null
b_gone() { ! has_peer dwg51820 "$PUB_B"; }
wait_for 5 "revoked b leaves dwg51820" b_gone
check "a cannot reach b any more" ping_fails a "$ADDR_B"

# 7. SIGTERM -> graceful server stop, even with the hub's long-poll open.
STOP_START=$(now_ms)
docker stop "$P-acs" >/dev/null
STOP_MS=$(($(now_ms) - STOP_START))
[ "$STOP_MS" -lt 5000 ] || fail "the server stops on SIGTERM within 5 s ($STOP_MS ms)"
ok "the server stops on SIGTERM within 5 s ($STOP_MS ms)"
# Last line `main` logs, terminal colours stripped.
stopped_logged() {
  docker logs "$P-acs" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E ' INFO dhonomos: stopped$'
}
check "the server logs that it stopped" stopped_logged
echo "server stopped; waiting one resync interval"
sleep 12
links_stay() { hub ip link show dwg51820 && hub ip link show dwg51821; }
check "dwg51820 and dwg51821 stay while the server is down" links_stay
check "a still reaches the hub while the server is down" ping_ok a 10.77.0.1
docker start "$P-acs" >/dev/null
wait_for 60 "the server is back" curl -sf http://172.31.30.3:8080/healthz
PUB_C2=$(api POST "/wireguard/networks/$N1/members" '{"kind":"client","name":"c2","user_id":null}' |
  jq -r .public_key)
c2_peered() { has_peer dwg51820 "$PUB_C2"; }
wait_for 15 "a new client member of N1 becomes a peer after the server is back" c2_peered

# 8.
stop_hub
api DELETE "/wireguard/networks/$N2" >/dev/null
ok "N2 deleted while the hub is stopped"
PLAN=$(dry_run) || fail "--dry-run runs"
echo "$PLAN" | sed 's/^/  dry run: /'
check "--dry-run plans to delete dwg51821" grep -qxF "delete interface dwg51821" <<<"$PLAN"
check "--dry-run plans to delete its rule" grep -qxF "delete rule iif dwg51821 table 151821" <<<"$PLAN"
check "--dry-run changed nothing: dwg51821 is still there" hub ip link show dwg51821
start_hub
n2_gone() { link_gone dwg51821 && no_rule dwg51821 && [ -z "$(table 151821)" ]; }
wait_for 10 "dwg51821, its rule and table 151821 are gone" n2_gone
check "wg0 and table inet e2e_foreign are still untouched" foreign_untouched

# 9.
nothing_to_do() { [ "$(dry_run)" = "no changes" ]; }
wait_for 10 "--dry-run prints no changes" nothing_to_do

echo "all checks passed"
