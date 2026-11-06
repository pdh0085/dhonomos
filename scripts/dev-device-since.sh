#!/usr/bin/env bash
# Dev server actions for one device since a moment: log lines (+ every WARN/ERROR),
# tasks, events (no periodic Informs).
# Covers CWMP + USP record of the same serial.
# Use: check field drills (e.g. uplink failover) from the server side.
#
# usage: scripts/dev-device-since.sh <serial> <UTC prefix>
#   e.g. scripts/dev-device-since.sh B01408123456 2026-10-16T05:10
#
# Reads dev server log (DHONOMOS_DEV_LOG, default
# ~/.local/state/dhonomos-dev/dhonomos.log) + its PostgreSQL container
# (DHONOMOS_DEV_PG, default dhonomos-dev-postgres-1).
set -euo pipefail
if [ $# -ne 2 ]; then
  sed -n 's/^# \{0,1\}//; 7,8p' "$0" >&2
  exit 2
fi
SERIAL="$1"
SINCE="$2"
LOG="${DHONOMOS_DEV_LOG:-$HOME/.local/state/dhonomos-dev/dhonomos.log}"
PG="${DHONOMOS_DEV_PG:-dhonomos-dev-postgres-1}"
case "$SERIAL" in *[!A-Za-z0-9_-]*) echo "bad serial: $SERIAL" >&2; exit 2;; esac
case "$SINCE" in *[!0-9T:.-]*) echo "bad time: $SINCE" >&2; exit 2;; esac
# Minute of the prefix, for SQL.
MINUTE=$(echo "$SINCE" | cut -c1-16)

psql() { docker exec "$PG" psql -U dhonomos -d dhonomos "$@"; }

IDS=$(psql -At -c "select string_agg(quote_literal(id::text), ',') from devices where serial_number = '$SERIAL'")
if [ -z "$IDS" ]; then
  echo "no device with serial $SERIAL" >&2
  exit 1
fi
# Log lines name a device by serial, EndpointID or record ID.
PATTERN="$SERIAL|$(psql -At -c "select string_agg(id::text, '|') from devices where serial_number = '$SERIAL'")|WARN|ERROR"

date -u
sed 's/\x1b\[[0-9;]*m//g' "$LOG" \
  | awk -v t="$SINCE" 'substr($0, 1, length(t)) >= t' \
  | grep -E "$PATTERN" | grep -vE " (DEBUG|TRACE) " | cut -c1-230 || true
psql -c "select left(device_id::text, 8) dev, kind, state, created_by, created_at::time(3) c,
  started_at::time(3) s, finished_at::time(3) f, error, left(payload::text, 40) p
  from tasks where device_id in ($IDS) and created_at >= '${MINUTE}:00+00' order by created_at"
psql -At -c "select occurred_at::time(3), left(device_id::text, 8), kind, left(detail::text, 140)
  from events where device_id in ($IDS) and occurred_at >= '${MINUTE}:00+00'
  and not (kind = 'inform' and detail::text like '%\"2 PERIODIC\"]%') order by occurred_at"
psql -At -c "select left(id::text, 8), protocol, status, software_version from devices where serial_number = '$SERIAL'"
