#!/usr/bin/env bash
# Wait for a boot of each given CWMP device after <since>, or until <deadline>.
# Use: field drills from the server side (e.g. after firmware flash or power cut).
# Done = each serial has an Inform event with '1 BOOT' newer than <since> -> next drill step.
# Else -> list of serials not back in time.
#
# usage: scripts/dev-wait-boot.sh <since> <deadline> <serial>...
#   e.g. scripts/dev-wait-boot.sh 2026-10-19T09:10:00 2026-10-19T09:40 B01408123456 B01408123457
#     since      Only a boot after this counts. Any 'date -d' input, as UTC.
#     deadline   Give up then. Any 'date -d' input, as UTC (e.g. '+30 minutes').
#     serial     Serial of a CWMP device (letters, digits, '_', '-').
#
# Polls dev server PostgreSQL container (DHONOMOS_DEV_PG, default dhonomos-dev-postgres-1)
# every 15 s (DHONOMOS_WAIT_INTERVAL, in s). CWMP record only: USP Agent Boot! != Inform event.
#
# Output: all booted -> 'all booted HH:MM:SS' (UTC), exit 0.
# Deadline -> 'deadline reached HH:MM:SS; still waiting for: <serials>', exit 1.
# Device with no record yet -> waited for like any other.
# Exit 2: bad arguments or missing tool. Exit 3: DB query fails.
set -euo pipefail
if [ $# -lt 3 ]; then
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0" >&2
  exit 2
fi
PG="${DHONOMOS_DEV_PG:-dhonomos-dev-postgres-1}"
INTERVAL="${DHONOMOS_WAIT_INTERVAL:-15}"
case "$INTERVAL" in ''|*[!0-9]*|0) echo "bad DHONOMOS_WAIT_INTERVAL: $INTERVAL" >&2; exit 2;; esac
command -v docker >/dev/null 2>&1 || { echo "missing tool: docker" >&2; exit 2; }

# Both times via date -> SQL below gets only digits, '-', ':', '.'.
SINCE_SQL=$(date -u -d "$1" '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null) \
  || { echo "bad time: $1" >&2; exit 2; }
DEADLINE=$(date -u -d "$2" +%s 2>/dev/null) || { echo "bad time: $2" >&2; exit 2; }
shift 2

SERIALS=()
for s in "$@"; do
  case "$s" in ''|*[!A-Za-z0-9_-]*) echo "bad serial: $s" >&2; exit 2;; esac
  case " ${SERIALS[*]-} " in *" $s "*) continue;; esac
  SERIALS+=("$s")
done
LIST=$(printf "'%s'," "${SERIALS[@]}")
LIST="${LIST%,}"

psql() { docker exec "$PG" psql -U dhonomos -d dhonomos "$@"; }

# Serials with an Inform '1 BOOT' after SINCE, 1 per line.
booted() {
  psql -At -c "select distinct d.serial_number from events e join devices d on d.id = e.device_id
    where d.protocol = 'cwmp' and d.serial_number in ($LIST) and e.kind = 'inform'
    and e.detail->'events' ? '1 BOOT' and e.occurred_at > '${SINCE_SQL}+00'"
}

if ! psql -At -c 'select 1' >/dev/null 2>&1; then
  echo "cannot query the database in container $PG" >&2
  exit 3
fi

while :; do
  # Failed poll -> retry at next poll; deadline decides.
  seen=$(booted 2>/dev/null) || seen=""
  missing=()
  for s in "${SERIALS[@]}"; do
    case $'\n'"$seen"$'\n' in *$'\n'"$s"$'\n'*) ;; *) missing+=("$s");; esac
  done
  if [ ${#missing[@]} -eq 0 ]; then
    echo "all booted $(date -u +%T)"
    exit 0
  fi
  left=$((DEADLINE - $(date -u +%s)))
  if [ "$left" -le 0 ]; then
    echo "deadline reached $(date -u +%T); still waiting for: ${missing[*]}"
    exit 1
  fi
  sleep $((left < INTERVAL ? left : INTERVAL))
done
