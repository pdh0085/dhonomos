#!/usr/bin/env bash
# Log device-facing TCP sockets of the dev server, 1 sample/s, until an end time.
# Use: server-side evidence for uplink-switch drills in the field (device logs out of reach
# while its uplink is down). Kernel view per flow:
#   - flow alive?        segs_in / segs_out count up, or stand still
#   - last byte when?    lastrcv (ms ago); lastack = last ACK we got
#   - peer answers?      retrans + keepalive timer (flow gone right after a probe ->
#     sample shows ACK or RST for the probe)
# Flow in one sample, gone in the next -> ended in between. New peer port for the same
# device -> new flow (device reconnected, e.g. via the other uplink).
#
# Usage:
#   scripts/dev-socket-log.sh [--ports LIST] [--exclude LIST] <out file> <end time>
#     out file          Appended (created if missing); directory must exist.
#     end time          Stop time; anything 'date -d' reads, as UTC,
#                       e.g. 2026-10-19T09:30 or '+2 hours'.
#     --ports LIST      Comma-separated server ports; established connections are logged
#                       (default 61614,7547,5222,7549,8883 = USP over STOMP/TLS,
#                       CWMP ACS, XMPP, USP over WebSocket (wss), USP over MQTT/TLS;
#                       env DHONOMOS_SOCKET_PORTS)
#     --exclude LIST    Comma-separated peer address prefixes to skip -> private LAN + host
#                       not logged (default 10.,192.168.,127.; env DHONOMOS_SOCKET_EXCLUDE).
#                       IPv4-mapped IPv6 peer -> compared in IPv4 form.
#
# Output: 1 sample/s, each starts with a '### HH:MM:SS.mmm' line (UTC), then 1 line per
# established socket ('ss -tnoi' gives 2 lines per socket, joined with paste):
#   <Recv-Q> <Send-Q> <local addr:port> <peer addr:port> timer:(...) <tab> <ss -i details>
# Nothing after the '###' line -> no device-facing socket open at that moment.
#
# Summary afterwards, e.g. first + last sample per peer of port 7549
# (key = peer address:port -> reconnect = new row):
#   awk -v port=7549 '/^###/ { t = $2; next }
#       $3 ~ (":" port "$") { if (!($4 in first)) first[$4] = t; last[$4] = t }
#       END { for (p in first) print first[p], last[p], p }' FILE | sort
# Counters of one flow over time (segs_in, lastrcv, lastack):
#   awk '/^###/ { t = $2; next } $4 == "203.0.113.9:51514" {
#       match($0, /segs_in:[0-9]+/); si = substr($0, RSTART, RLENGTH)
#       match($0, /lastrcv:[0-9]+/); lr = substr($0, RSTART, RLENGTH); print t, si, lr }' FILE
#
# Needs ss (iproute2) + GNU date. SIGINT/SIGTERM -> early stop; samples already written stay.
#
# Exit: 0 end time reached, 2 bad arguments or missing tool, 1 output file not writable.
set -uo pipefail

ports="${DHONOMOS_SOCKET_PORTS:-61614,7547,5222,7549,8883}"
exclude="${DHONOMOS_SOCKET_EXCLUDE:-10.,192.168.,127.}"
positional=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports) [[ $# -ge 2 ]] || { echo "--ports needs a value" >&2; exit 2; }; ports="$2"; shift 2 ;;
    --exclude) [[ $# -ge 2 ]] || { echo "--exclude needs a value" >&2; exit 2; }; exclude="$2"; shift 2 ;;
    -h|--help)
      awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
      exit 0 ;;
    --) shift; positional+=("$@"); break ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) positional+=("$1"); shift ;;
  esac
done
if [[ ${#positional[@]} -ne 2 ]]; then
  echo "usage: $0 [--ports LIST] [--exclude LIST] <out file> <end time>   (--help for more)" >&2
  exit 2
fi
out="${positional[0]}"
end_time="${positional[1]}"

for tool in ss date awk paste; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 2; }
done

# Ports: digits only, 1..65535 -> safe in the ss filter expression.
filter=""
IFS=',' read -r -a port_list <<<"$ports"
[[ ${#port_list[@]} -gt 0 ]] || { echo "bad --ports: $ports" >&2; exit 2; }
for p in "${port_list[@]}"; do
  case "$p" in
    ''|*[!0-9]*) echo "bad port: '$p' (--ports is a comma-separated list of numbers)" >&2; exit 2 ;;
  esac
  if [[ $((10#$p)) -lt 1 || $((10#$p)) -gt 65535 ]]; then
    echo "bad port: $p (1..65535)" >&2; exit 2
  fi
  filter+="${filter:+ or }sport = :$((10#$p))"
done

# Excluded prefixes: address chars only (digits, hex, '.', ':').
# Compared as plain text with the peer address start, never as a pattern.
IFS=',' read -r -a prefix_list <<<"$exclude"
for x in "${prefix_list[@]}"; do
  case "$x" in
    *[!0-9A-Fa-f.:]*) echo "bad address prefix: '$x' (--exclude is a comma-separated list such as 10.,192.168.,127.)" >&2; exit 2 ;;
  esac
done
exclude_joined="$(IFS=,; echo "${prefix_list[*]}")"

end_epoch="$(date -u -d "$end_time" +%s 2>/dev/null)" \
  || { echo "cannot read the end time '$end_time' (see 'man date')" >&2; exit 2; }
if [[ "$end_epoch" -le "$(date -u +%s)" ]]; then
  echo "the end time $end_time is not in the future" >&2
  exit 2
fi
{ : >>"$out"; } 2>/dev/null || { echo "cannot write $out" >&2; exit 1; }

# 1 sample: established sockets of the ports, 2 ss lines -> 1, excluded peer prefixes dropped.
sample() {
  ss -tnoi state established "( $filter )" \
    | awk '!/^Recv-Q/' \
    | paste - - \
    | awk -v prefixes="$exclude_joined" '
        BEGIN { n = split(prefixes, pre, ",") }
        {
          peer = $4
          sub(/^\[/, "", peer)
          sub(/^::[fF][fF][fF][fF]:/, "", peer)
          for (i = 1; i <= n; i++) {
            if (pre[i] != "" && index(peer, pre[i]) == 1) next
          }
          print
        }'
}

while [[ "$(date -u +%s)" -lt "$end_epoch" ]]; do
  stamp="$(date -u +%H:%M:%S.%3N)"
  lines="$(sample)"
  {
    printf '### %s\n' "$stamp"
    [[ -z "$lines" ]] || printf '%s\n' "$lines"
  } >>"$out" || { echo "cannot write $out" >&2; exit 1; }
  sleep 1
done
