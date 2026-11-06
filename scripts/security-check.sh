#!/usr/bin/env bash
# One-shot, read-only security check of a Dhonomos host, before + after the web UI goes public.
# Changes nothing. Reads: running server settings, listening sockets, firewall (if allowed),
# file permissions, a few unauthenticated API answers.
# Secret values never printed; only set or not + length.
#
# Usage:
#   scripts/security-check.sh [--api URL] [--public-url URL] [--env FILE]
#     --api URL         API as this host reaches it (default: from DHONOMOS_API_LISTEN,
#                       else http://127.0.0.1:8080)
#     --public-url URL  Address users open from the internet, e.g.
#                       https://rms.example.org (-> checks TLS, HSTS + open mode through it)
#     --env FILE        Settings file to read if no running server found
#                       (default: .env.dev in the repository of this script)
#   DHONOMOS_CHECK_TOKEN=<admin API key> -> also checks accounts (admins without two-factor).
#   Run with sudo (or as root) -> also ufw firewall rules.
#
# Exit status: 0 all good, 1 warnings only, 2 >= 1 failure.
set -uo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
api=""
public_url=""
env_file="$repo/.env.dev"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api) api="${2:?}"; shift 2 ;;
    --public-url) public_url="${2%/}"; shift 2 ;;
    --env) env_file="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

if [[ -t 1 ]]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R=; Y=; G=; B=; N=; fi
fails=0; warns=0
pass() { printf '  %sPASS%s %s\n' "$G" "$N" "$*"; }
warn() { printf '  %sWARN%s %s\n' "$Y" "$N" "$*"; warns=$((warns + 1)); }
fail() { printf '  %sFAIL%s %s\n' "$R" "$N" "$*"; fails=$((fails + 1)); }
info() { printf '  info %s\n' "$*"; }
section() { printf '\n%s== %s%s\n' "$B" "$*" "$N"; }
need() { command -v "$1" >/dev/null 2>&1; }

for tool in curl ss python3; do
  need "$tool" || { echo "missing tool: $tool" >&2; exit 64; }
done

# ---------------------------------------------------------------------------------------
section "Server process and settings"
declare -A cfg=()
pids="$(pgrep -x dhonomos 2>/dev/null || true)"
pid="$(head -n1 <<<"$pids")"
if [[ -n "$pid" ]]; then
  exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo '?')"
  if [[ "$exe" == *' (deleted)' ]]; then
    exe="${exe% (deleted)}"
    warn "the binary was rebuilt after pid $pid started: restart it to run the current code"
  fi
  info "running: pid $pid ($exe)"
  [[ "$(wc -l <<<"$pids")" -gt 1 ]] && info "more than one dhonomos process: checking pid $pid"
  if [[ -r "/proc/$pid/environ" ]]; then
    while IFS= read -r -d '' kv; do
      [[ "$kv" == DHONOMOS_* ]] && cfg["${kv%%=*}"]="${kv#*=}"
    done <"/proc/$pid/environ"
    info "settings read from the running process"
  else
    info "cannot read the process environment (other user); using $env_file"
  fi
  case "$exe" in
    */target/debug/*) warn "debug build is running; expose only a release build" ;;
    '?') ;;
    *) pass "not a debug build" ;;
  esac
else
  warn "no running dhonomos process found; checking settings from $env_file only"
fi
if [[ ${#cfg[@]} -eq 0 && -r "$env_file" ]]; then
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*(DHONOMOS_[A-Z0-9_]+)=(.*)$ ]] || continue
    v="${BASH_REMATCH[2]}"; v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    cfg["${BASH_REMATCH[1]}"]="$v"
  done <"$env_file"
fi
get() { printf '%s' "${cfg[$1]:-}"; }
is_true() { [[ "${1,,}" =~ ^(1|true|yes|on)$ ]]; }
is_false() { [[ "${1,,}" =~ ^(0|false|no|off)$ ]]; }

api_listen="$(get DHONOMOS_API_LISTEN)"; api_listen="${api_listen:-127.0.0.1:8080}"
[[ -z "$api" ]] && api="http://${api_listen/0.0.0.0/127.0.0.1}"
api="${api%/}"

if is_true "$(get DHONOMOS_API_ALLOW_OPEN)"; then
  fail "DHONOMOS_API_ALLOW_OPEN is on: the API may run without accounts for anyone who reaches it"
else
  pass "API_ALLOW_OPEN is off"
fi
if [[ -n "$(get DHONOMOS_API_TOKEN)" ]]; then
  warn "DHONOMOS_API_TOKEN is set (${#cfg[DHONOMOS_API_TOKEN]} chars): an admin credential that never expires; unset it unless a machine needs it, and never paste it into a browser"
else
  pass "no static API token"
fi
trusted_proxies="$(get DHONOMOS_TRUSTED_PROXIES)"
server_public_url="$(get DHONOMOS_PUBLIC_URL)"
if is_true "$(get DHONOMOS_SECURE_COOKIES)"; then
  pass "SECURE_COOKIES is on (session cookie is Secure and named __Host-dhonomos_session)"
elif [[ -n "$public_url" ]]; then
  fail "SECURE_COOKIES is off: session cookies lack Secure and the __Host- prefix behind the HTTPS proxy"
elif [[ -n "$trusted_proxies" || "$server_public_url" == https://* ]]; then
  warn "SECURE_COOKIES is off although a proxy or an https PUBLIC_URL is configured: turn it on"
else
  warn "SECURE_COOKIES is off: turn it on before serving the UI over HTTPS"
fi
# Roles with two-factor required: REQUIRE_TOTP_ROLES (default admin).
# REQUIRE_ADMIN_TOTP, if set -> adds (true) or removes (false) admin.
declare -A totp_roles=()
IFS=',' read -ra listed <<<"$(get DHONOMOS_REQUIRE_TOTP_ROLES)"
[[ -z "$(get DHONOMOS_REQUIRE_TOTP_ROLES)" ]] && listed=(admin)
for role in "${listed[@]}"; do
  role="${role// /}"; role="${role,,}"
  case "$role" in admin|operator|viewer) totp_roles[$role]=1 ;; esac
done
if is_true "$(get DHONOMOS_REQUIRE_ADMIN_TOTP)"; then totp_roles[admin]=1
elif is_false "$(get DHONOMOS_REQUIRE_ADMIN_TOTP)"; then unset 'totp_roles[admin]'; fi
roles_text=""
for role in admin operator viewer; do
  [[ -n "${totp_roles[$role]:-}" ]] && roles_text+="${roles_text:+,}$role"
done
if [[ -z "${totp_roles[admin]:-}" ]]; then
  fail "REQUIRE_TOTP_ROLES does not include admin ('${roles_text:-none}'): admins can log in with a password alone"
else
  pass "two-factor is required for: $roles_text (REQUIRE_TOTP_ROLES)"
  if [[ -z "${totp_roles[operator]:-}" ]]; then
    if [[ -n "$public_url" ]]; then
      warn "operators are not required to use two-factor: they can reach every device and start fleet-wide jobs with a password alone; set DHONOMOS_REQUIRE_TOTP_ROLES=admin,operator"
    else
      info "operators are not required to use two-factor (DHONOMOS_REQUIRE_TOTP_ROLES=admin,operator would)"
    fi
  fi
fi
if [[ -n "$trusted_proxies" ]]; then
  wide=""
  IFS=',' read -ra nets <<<"$trusted_proxies"
  for net in "${nets[@]}"; do
    net="${net// /}"; plen="${net#*/}"
    [[ "$net" == */* && "$plen" =~ ^[0-9]+$ && "$plen" -lt 8 ]] && wide+=" $net"
  done
  if [[ -n "$wide" ]]; then
    fail "TRUSTED_PROXIES trusts a very wide network (${wide# }): anyone in it can forge the client address; list only the proxy's own address"
  else
    pass "TRUSTED_PROXIES is set ($trusted_proxies): forwarded client addresses are believed from it only"
  fi
elif [[ -n "$public_url" || -n "$server_public_url" ]]; then
  warn "TRUSTED_PROXIES is not set: behind the proxy every visitor counts as the proxy's address, so one visitor can use up the rate limits and lock out every login; set DHONOMOS_TRUSTED_PROXIES=127.0.0.1/32"
else
  info "TRUSTED_PROXIES is not set (right without a reverse proxy)"
fi
if [[ -n "$server_public_url" ]]; then
  if [[ "$server_public_url" != https://* ]]; then
    warn "PUBLIC_URL ($server_public_url) is not https"
  elif [[ -n "$public_url" && "${server_public_url,,}" != "${public_url,,}" ]]; then
    warn "PUBLIC_URL ($server_public_url) differs from --public-url ($public_url): browsers' change requests from $public_url are refused"
  else
    pass "PUBLIC_URL is $server_public_url: the cross-site request check compares against it exactly"
  fi
elif [[ -n "$public_url" ]]; then
  warn "PUBLIC_URL is not set: the cross-site request check falls back to the Host header; set DHONOMOS_PUBLIC_URL=$public_url"
else
  info "PUBLIC_URL is not set (set it to the https address once the UI is published)"
fi
idle="$(get DHONOMOS_SESSION_IDLE_MINUTES)"
if [[ -z "$idle" ]]; then
  pass "idle sessions end after 60 minutes (SESSION_IDLE_MINUTES default)"
elif ! [[ "$idle" =~ ^[0-9]+$ ]]; then
  warn "SESSION_IDLE_MINUTES='$idle' is not a number"
elif [[ "$idle" -eq 0 ]]; then
  warn "SESSION_IDLE_MINUTES=0: a session never ends for being unused (only by its lifetime)"
elif [[ "$idle" -gt 120 ]]; then
  warn "SESSION_IDLE_MINUTES=$idle: unused sessions stay open for more than 2 hours"
else
  pass "idle sessions end after $idle minutes"
fi
sk="$(get DHONOMOS_SECRETS_KEY)"
if [[ -n "$sk" ]]; then pass "SECRETS_KEY is set (${#sk} chars)"; else warn "SECRETS_KEY is not set: stored secrets and two-factor need it"; fi
fs="$(get DHONOMOS_FILES_SECRET)"
if [[ -z "$fs" ]]; then info "FILES_SECRET not set: a random key is made at each start (signed links break on restart)"
elif [[ ${#fs} -lt 32 ]]; then fail "FILES_SECRET is ${#fs} chars; it must be at least 32"
else pass "FILES_SECRET is ${#fs} chars"; fi
sh="$(get DHONOMOS_SESSION_HOURS)"
if [[ -n "$sh" && "$sh" =~ ^[0-9]+$ && "$sh" -gt 12 ]]; then warn "SESSION_HOURS=$sh: sessions longer than 12 h"
elif [[ -n "$public_url" && ( -z "$sh" || ( "$sh" =~ ^[0-9]+$ && "$sh" -gt 8 ) ) ]]; then info "SESSION_HOURS=${sh:-12} (default 12): consider 8 for a UI on the internet"; fi
if is_true "$(get DHONOMOS_ACS_PLAINTEXT)"; then warn "ACS runs without TLS (ACS_PLAINTEXT): device secrets travel in clear"; fi
if [[ "$(get DHONOMOS_CPE_AUTH)" == none ]]; then fail "CPE_AUTH=none: any CPE can register and impersonate devices"; fi
if [[ -n "$(get DHONOMOS_USP_WS_LISTEN)" ]]; then
  if [[ "$(get DHONOMOS_USP_WS_CLIENT_CERT)" == required ]]; then pass "USP WebSocket requires client certificates"
  else warn "USP WebSocket does not require client certificates (USP_WS_CLIENT_CERT)"; fi
  is_true "$(get DHONOMOS_USP_WS_ALLOW_ANONYMOUS)" && warn "USP_WS_ALLOW_ANONYMOUS is on"
fi
is_true "$(get DHONOMOS_USP_STOMP_ALLOW_ANONYMOUS)" && warn "USP_STOMP_ALLOW_ANONYMOUS is on"
is_true "$(get DHONOMOS_USP_MQTT_BROKER_ALLOW_ANONYMOUS)" && warn "USP_MQTT_BROKER_ALLOW_ANONYMOUS is on"
if [[ -n "$(get DHONOMOS_USP_MQTT_BROKER_LISTEN)" ]] && ! is_true "$(get DHONOMOS_USP_MQTT_BROKER_TLS)"; then
  warn "embedded MQTT broker without TLS: the shared Agent password travels in clear"
fi

# ---------------------------------------------------------------------------------------
section "Listening sockets"
# Public addresses of this host (globally routable, per Python ipaddress).
mapfile -t public_ips < <(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | python3 -c '
import sys, ipaddress
for l in sys.stdin:
    try:
        a = ipaddress.ip_address(l.strip())
    except ValueError:
        continue
    if a.is_global:
        print(a)')
if [[ ${#public_ips[@]} -gt 0 ]]; then
  info "this host has public address(es): ${public_ips[*]}"
else
  info "no public address on this host's interfaces (NAT or firewall decides exposure)"
fi
is_public_bind() { # wildcard or public address of this host
  local a="$1"
  [[ "$a" == 0.0.0.0 || "$a" == '*' || "$a" == '[::]' || "$a" == '::' ]] && return 0
  local p; for p in "${public_ips[@]}"; do [[ "$a" == "$p" || "$a" == "[$p]" ]] && return 0; done
  return 1
}
api_port="${api_listen##*:}"
found=0
while read -r local proc; do
  found=1
  addr="${local%:*}"; port="${local##*:}"
  label="port $port"
  case "$port" in
    "$api_port") label="API/UI $port" ;;
    7547) label="ACS 7547" ;; 7548) label="file server 7548" ;; 7549) label="USP WebSocket 7549" ;;
    61614) label="USP STOMP 61614" ;; 8883) label="USP MQTT 8883" ;; 1883) label="USP MQTT 1883" ;;
  esac
  if is_public_bind "$addr"; then
    if [[ "$port" == "$api_port" ]]; then
      fail "$label listens on $addr: serve it only on loopback behind the TLS proxy"
    elif [[ ${#public_ips[@]} -gt 0 ]]; then
      warn "$label listens on $addr, which includes the public address: bind it to the device network (e.g. 10.20.30.1) or make sure the firewall blocks it"
    else
      info "$label listens on $addr"
    fi
  else
    pass "$label listens on $addr only"
  fi
done < <(ss -ltnpH 2>/dev/null | awk '/"dhonomos"/ {print $4, $6}')
[[ $found -eq 0 ]] && info "no dhonomos TCP listeners found (not running, or another user's process)"

# ---------------------------------------------------------------------------------------
section "Firewall (ufw)"
ufw_out=""
if [[ $EUID -eq 0 ]] && need ufw; then
  ufw_out="$(ufw status 2>&1)"
elif need sudo && sudo -n true 2>/dev/null; then
  ufw_out="$(sudo -n ufw status 2>&1)"
fi
if [[ -z "$ufw_out" ]]; then
  info "skipped: run with sudo to check the firewall rules"
elif grep -q 'Status: inactive' <<<"$ufw_out"; then
  if [[ ${#public_ips[@]} -gt 0 ]]; then fail "ufw is inactive on a host with a public address"; else warn "ufw is inactive"; fi
else
  pass "ufw is active"
  for port in "$api_port" 7547 7548 7549 61614 8883; do
    while read -r rule; do
      [[ -z "$rule" ]] && continue
      if grep -qE 'Anywhere' <<<"$rule" && ! grep -qE ' on [a-z]' <<<"$rule"; then
        warn "ufw allows port $port from anywhere on every interface: $rule"
      else
        info "ufw rule: $rule"
      fi
    done < <(grep -E "^${port}(/tcp)?[[:space:]]" <<<"$ufw_out" | grep -i allow)
  done
fi

# ---------------------------------------------------------------------------------------
section "API as this host sees it ($api)"
json_field() { python3 -c 'import json,sys
try: print(json.load(sys.stdin).get(sys.argv[1], ""))
except Exception: print("")' "$1"; }
if code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$api/healthz")" && [[ "$code" == 200 ]]; then
  pass "API answers (/healthz)"
  via="$(curl -s --max-time 5 "$api/api/v1/auth/me" | json_field via)"
  direct_open=0
  if [[ "$via" == open ]]; then
    direct_open=1
    warn "NO ACCOUNTS: every direct local caller is admin (open mode). Requests through a proxy are refused, but create an admin account before exposing the UI."
  else
    pass "unauthenticated callers are refused"
  fi
  via="$(curl -s --max-time 5 -H 'X-Forwarded-For: 203.0.113.7' -H 'X-Forwarded-Proto: https' "$api/api/v1/auth/me" | json_field via)"
  if [[ "$via" == open ]]; then
    fail "a request that came through a proxy (X-Forwarded-For) also gets admin: this server predates the open-mode fix (ADR-103); restart it with the current build"
  else
    pass "a request that carries proxy headers never gets open mode"
  fi
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$api/metrics")"
  case "$code" in 401|403) pass "/metrics needs a login ($code)" ;;
    200) [[ $direct_open -eq 1 ]] && info "/metrics open (open mode)" || fail "/metrics answers without a login" ;;
    *) info "/metrics answered $code" ;; esac
  hdrs="$(curl -s -D - -o /dev/null --max-time 5 "$api/" | tr -d '\r')"
  grep -qi '^x-frame-options: *deny' <<<"$hdrs" && pass "X-Frame-Options DENY" || warn "X-Frame-Options missing"
  grep -qi "^content-security-policy:.*frame-ancestors 'none'" <<<"$hdrs" && pass "CSP frame-ancestors 'none'" || warn "CSP frame-ancestors missing"
  grep -qi '^x-content-type-options: *nosniff' <<<"$hdrs" && pass "X-Content-Type-Options nosniff" || warn "nosniff missing"
  info "/api/v1/openapi.json and /api/v1/auth/config are public by design (API description, whether SSO is on)"
else
  warn "API at $api does not answer (code ${code:-none}); API checks skipped"
fi

# ---------------------------------------------------------------------------------------
section "Accounts"
if [[ -n "${DHONOMOS_CHECK_TOKEN:-}" ]]; then
  users="$(curl -s --max-time 10 -H "Authorization: Bearer $DHONOMOS_CHECK_TOKEN" "$api/api/v1/users")"
  while IFS='|' read -r level msg; do
    case "$level" in FAIL) fail "$msg" ;; WARN) warn "$msg" ;; *) info "$msg" ;; esac
  done < <(python3 - "$users" <<'PY'
import json, sys
try:
    items = json.loads(sys.argv[1]).get("items")
except Exception:
    items = None
if items is None:
    print("WARN|could not list users with DHONOMOS_CHECK_TOKEN (needs an admin API key)")
    sys.exit(0)
admins = [u for u in items if u.get("role") == "admin" and not u.get("disabled")]
print(f"INFO|{len(items)} account(s), {len(admins)} active admin(s)")
for u in admins:
    name = u.get("username") or u.get("name") or "?"
    if name.startswith("sso:"):
        continue
    if not u.get("totp_enabled"):
        print(f"FAIL|admin '{name}' has no two-factor yet")
    if name.lower() in ("admin", "administrator", "root"):
        print(f"WARN|admin name '{name}' is easy to guess (anyone can lock it out with failed logins)")
PY
)
else
  info "skipped: set DHONOMOS_CHECK_TOKEN=<admin API key> to check admins without two-factor"
fi

# ---------------------------------------------------------------------------------------
section "Files and keys on disk"
mode_of() { stat -c '%a' "$1" 2>/dev/null; }
files_dir="$(get DHONOMOS_FILES_DIR)"; files_dir="${files_dir:-data/files}"
[[ "$files_dir" != /* ]] && files_dir="$repo/$files_dir"
if [[ -d "$files_dir" ]]; then
  m="$(mode_of "$files_dir")"
  if [[ "${m: -2}" == 00 ]]; then pass "files dir $files_dir is owner-only ($m)"; else warn "files dir $files_dir is mode $m (config backups may hold secrets): chmod 700"; fi
  loose="$(find "$files_dir" -maxdepth 1 -type f -perm /077 2>/dev/null | wc -l)"
  if [[ "$loose" -gt 0 ]]; then warn "$loose stored file(s) readable by group/others: chmod 600 $files_dir/*"; else pass "stored files are owner-only"; fi
fi
ca_dir="$(get DHONOMOS_USP_CA_DIR)"; ca_dir="${ca_dir/#\~/$HOME}"
if [[ -n "$ca_dir" && -f "$ca_dir/ca.key" ]]; then
  m="$(mode_of "$ca_dir/ca.key")"
  [[ "$m" == 600 || "$m" == 400 ]] && pass "USP CA key is owner-only ($m)" || fail "USP CA key $ca_dir/ca.key is mode $m: chmod 600"
  [[ "$ca_dir" == "$repo"/* ]] && warn "USP CA directory is inside the repository: keep it outside"
fi
if [[ -f "$env_file" ]]; then
  m="$(mode_of "$env_file")"
  [[ "${m: -2}" == 00 ]] && pass "$(basename "$env_file") is owner-only ($m)" || warn "$env_file is mode $m: chmod 600"
  if git -C "$repo" ls-files --error-unmatch "$env_file" >/dev/null 2>&1; then fail "$env_file is tracked by git"; fi
fi

# ---------------------------------------------------------------------------------------
section "Certificates of the device listeners"
if need openssl; then
  for name in USP_WS_LISTEN USP_STOMP_LISTEN USP_MQTT_BROKER_LISTEN ACS_LISTEN; do
    l="$(get "DHONOMOS_$name")"; [[ -z "$l" ]] && continue
    host="${l%:*}"; port="${l##*:}"; [[ "$host" == 0.0.0.0 || "$host" == '[::]' ]] && host=127.0.0.1
    end="$(echo | timeout 5 openssl s_client -connect "$host:$port" -servername "$host" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
    [[ -z "$end" ]] && { info "$name ($host:$port): no TLS certificate (plaintext, or not reachable)"; continue; }
    days=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 ))
    if [[ $days -lt 0 ]]; then fail "$name certificate expired $((-days)) day(s) ago"
    elif [[ $days -lt 14 ]]; then warn "$name certificate expires in $days day(s)"
    else pass "$name certificate valid for $days more day(s)"; fi
  done
fi

# ---------------------------------------------------------------------------------------
if [[ -n "$public_url" ]]; then
  section "Public URL ($public_url)"
  if [[ "$public_url" != https://* ]]; then
    fail "the public URL is not HTTPS"
  elif code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$public_url/healthz")" && [[ "$code" =~ ^[23] ]]; then
    pass "reachable with a valid TLS certificate"
    hdrs="$(curl -s -D - -o /dev/null --max-time 10 "$public_url/" | tr -d '\r')"
    grep -qi '^strict-transport-security:' <<<"$hdrs" && pass "HSTS sent" || fail "no Strict-Transport-Security header (set it at the proxy)"
    via="$(curl -s --max-time 10 "$public_url/api/v1/auth/me" | json_field via)"
    [[ "$via" == open ]] && fail "THE INTERNET IS ADMIN: $public_url/api/v1/auth/me answers in open mode"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$public_url/metrics")"
    [[ "$code" =~ ^(401|403|404)$ ]] && pass "/metrics not served publicly ($code)" || warn "/metrics answered $code through the public URL"
    plain="http://${public_url#https://}"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$plain/")"
    [[ "$code" =~ ^30[1278]$ ]] && pass "plain HTTP redirects to HTTPS" || info "plain HTTP answered $code"
  else
    curl -sS -o /dev/null --max-time 10 "$public_url/healthz" 2>&1 | sed 's/^/  /'
    fail "the public URL does not answer with a valid certificate"
  fi
  info "from outside, also verify that only 443 is open, e.g. 'nmap -Pn -p 22,80,443,1883,7547-7549,8080,8883,61614 <public address>'"
else
  section "Public URL"
  info "skipped: pass --public-url https://<name> once the proxy is set up"
fi

# ---------------------------------------------------------------------------------------
printf '\n%sSummary:%s %d failure(s), %d warning(s)\n' "$B" "$N" "$fails" "$warns"
info "not checked here: login lockout and rate limits behind the proxy, and the proxy's own rules (see docs/guide/operations.md section 2b)"
if [[ $fails -gt 0 ]]; then exit 2; elif [[ $warns -gt 0 ]]; then exit 1; else exit 0; fi
