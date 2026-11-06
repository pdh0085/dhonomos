#!/bin/sh
# Dynamic-security config on first start:
#   admin account -> Dhonomos manages Agent accounts with it;
#   Controller account (if DYNSEC_CONTROLLER_USERNAME is set) -> only USP sub/pub,
#   Controller role given by Dhonomos at start.
# Separate on purpose: admin password can create accounts + change ACLs, Controller's cannot.
set -e
f=/mosquitto/data/dynamic-security.json
admin="${DYNSEC_ADMIN_USERNAME:-admin}"
admin_password="${DYNSEC_ADMIN_PASSWORD:?set DYNSEC_ADMIN_PASSWORD}"
if [ ! -f "$f" ]; then
  mosquitto_ctrl dynsec init "$f" "$admin" "$admin_password" >/dev/null
  chown mosquitto "$f"
  if [ -n "${DYNSEC_CONTROLLER_USERNAME:-}" ]; then
    controller_password="${DYNSEC_CONTROLLER_PASSWORD:?set DYNSEC_CONTROLLER_PASSWORD}"
    # Broker on a local port only, just long enough to add the account.
    cat > /tmp/init.conf <<EOF
listener 18830 127.0.0.1
allow_anonymous false
persistence false
plugin /usr/lib/mosquitto_dynamic_security.so
plugin_opt_config_file $f
EOF
    mosquitto -c /tmp/init.conf >/dev/null 2>&1 &
    pid=$!
    created=
    for _ in $(seq 50); do
      if mosquitto_ctrl -h 127.0.0.1 -p 18830 -u "$admin" -P "$admin_password" dynsec \
        createClient "$DYNSEC_CONTROLLER_USERNAME" -p "$controller_password" >/dev/null 2>&1; then
        created=1
        break
      fi
      sleep 0.2
    done
    kill "$pid"
    wait "$pid" || true
    rm -f /tmp/init.conf
    [ -n "$created" ] || { echo "could not create the Controller account" >&2; exit 1; }
  fi
fi
exec mosquitto -c /mosquitto/config/dynsec.conf
