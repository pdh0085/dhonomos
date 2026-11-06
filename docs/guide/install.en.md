# Installation guide (10 minutes)

English translation of [install.md](install.md). The other guides in this directory are in
Korean for now.

Dhonomos needs one executable (`dhonomos`) and PostgreSQL 17. This guide starts it with
Docker Compose.

## 1. Requirements

- Docker 24 or later (with Compose v2), Linux on x86_64.
- Ports to open:
  - 7547/tcp: CWMP ACS.
  - 7548/tcp: file server (firmware downloads, configuration uploads, BulkData).
  - The API and web UI (8080/tcp) have no TLS. **Do not open them to the outside.** Compose
    publishes them on `127.0.0.1:8080` only; use them behind a TLS reverse proxy, as
    described in section 4.
  - With USP over an external broker: Mosquitto 1883 is published on loopback only by
    compose; open TLS 8883 for Agents on the network. The built-in MQTT broker uses TLS 8883.
  - With CPEs behind NAT: 3478/udp (STUN).

## 2. Build the image

```bash
git clone https://github.com/pdh0085/dhonomos.git && cd dhonomos
docker build -t dhonomos:dev .
```

The image holds only the statically linked `dhonomos` executable (base image `scratch`,
no components under other licenses).

There are no releases yet. Once there are, verify the downloaded artifacts first
(signature, then checksums; needs only OpenSSH):

```bash
scripts/verify-release.sh release/allowed_signers ./downloads 0.1.0
docker load < downloads/dhonomos-0.1.0-image.tar.gz
```

## 3. Configure

```bash
cp deploy/dhonomos.env.example deploy/dhonomos.env
openssl rand -base64 32   # a new value for each secret
```

The secrets in the example file are empty on purpose. Fill in:

- `POSTGRES_PASSWORD`
- `DHONOMOS_ADMIN_PASSWORD` (10 characters or more)
- `DHONOMOS_FILES_SECRET` (**32 bytes or more**; changing it invalidates existing links and
  STUN passwords)
- `DHONOMOS_SECRETS_KEY` (encrypts device credentials)
- `DHONOMOS_FILES_PUBLIC_URL` (the address at which CPEs reach the file server)
- `DHONOMOS_CPE_USERNAME` and `DHONOMOS_CPE_PASSWORD` (the shared CPE credentials; section 5)
- `DHONOMOS_ACS_TLS_CERT` and `DHONOMOS_ACS_TLS_KEY`, or `DHONOMOS_ACS_PLAINTEXT=true` in an
  isolated lab (section 5)

Dhonomos refuses to start when `DHONOMOS_FILES_SECRET` or `DHONOMOS_ADMIN_PASSWORD` is
`change-me`, `changeme`, `secret` or `password`, or contains `change-me`. It also refuses
a `--files-secret` shorter than 32 bytes: this one key signs download, upload and BulkData
links and derives the STUN passwords, so a single signed link would let anyone guess a short
key offline.

For HTTPS on the file server, set `DHONOMOS_FILES_TLS_CERT` and `DHONOMOS_FILES_TLS_KEY`
(PEM files) and write `DHONOMOS_FILES_PUBLIC_URL` with `https://`. Renewed certificate files
are picked up without a restart (operations guide, section 4c-1).

## 4. Start

```bash
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f dhonomos   # ready when "API listening" appears
```

Log in with `admin` / `DHONOMOS_ADMIN_PASSWORD` (on the server itself:
`http://127.0.0.1:8080`). Create operator accounts and API keys for automation under
Users & keys.

**Two-factor authentication is required for admin** (default), so the Account page
opens after the first login. Scan the QR code with an authenticator app, confirm a code,
and keep the 10 recovery codes shown in a safe place (details and what to do after losing
the phone: operations guide, section 3c). This needs `DHONOMOS_SECRETS_KEY`
(already in `deploy/dhonomos.env.example`). To turn it off in an isolated lab:
`DHONOMOS_REQUIRE_ADMIN_TOTP=false`.

### API and web UI behind a TLS reverse proxy

The API and web UI have no TLS of their own. To keep passwords and session cookies off the
wire, compose publishes 8080 on the host's `127.0.0.1` only. To use them from elsewhere, put
a TLS-terminating reverse proxy (nginx, Caddy, HAProxy...) on the same host or a trusted
internal network in front, and set `DHONOMOS_SECURE_COOKIES=true` in `deploy/dhonomos.env`
(session cookie with `Secure`). Example (Caddy; certificate obtained automatically):

```
dhonomos.example.net {
    reverse_proxy 127.0.0.1:8080
}
```

Opening the UI to the internet (trusted proxy addresses, public URL, roles that must use two
factors, session limits, an Apache example) is covered in section 2b of the operations guide
([operations.md](operations.md), Korean). When the API listens on a non-loopback address
with `DHONOMOS_SECURE_COOKIES` off, the log warns
`the API listens on a network address without --secure-cookies`. Inside the container the
address is `[::]:8080`, so with compose this warning means: set
`DHONOMOS_SECURE_COOKIES=true`.

## 5. Connect the first CPE

The ACS needs TLS to start: give `DHONOMOS_ACS_TLS_CERT` and `DHONOMOS_ACS_TLS_KEY` (PEM
files), or allow plain HTTP with `DHONOMOS_ACS_PLAINTEXT=true`, only behind a
TLS-terminating proxy or in an isolated lab (commented out in the example env).

Set the CPE's ACS URL to `https://<server>:7547/` (`http://` if plain HTTP is allowed).
After the first Inform the device appears in the device list and zero-touch reads all of its
parameters.

CPE authentication defaults to `DHONOMOS_CPE_AUTH=digest`; Dhonomos starts only with the
shared `DHONOMOS_CPE_USERNAME` and `DHONOMOS_CPE_PASSWORD`. Per-device credentials, issued at
zero-touch, come on top of them.
`DHONOMOS_CPE_AUTH=none` lets any client pose as any CPE, so it is for isolated labs only; on
a non-loopback address the log warns `the ACS takes CPEs without authentication`.

## 6. USP (optional)

```bash
docker compose -f deploy/docker-compose.yml --profile usp up -d
```

Uncomment the USP lines in `deploy/dhonomos.env` and Dhonomos manages Agent accounts through
Mosquitto dynamic-security. There are two broker accounts:

- **admin** (`dhonomos-admin`, `MQTT_ADMIN_PASSWORD`): creates Agent accounts and changes
  ACLs. Dhonomos uses it only for the dynsec connection.
- **Controller** (`dhonomos-controller`, `MQTT_CONTROLLER_PASSWORD`): only subscribes and
  publishes USP.

The two passwords must differ; the broker creates both accounts at its first start. A volume
made by an older compose file (one admin account `dhonomos` for both) keeps working; to split
it, create a Controller account with `mosquitto_ctrl` and point
`DHONOMOS_USP_MQTT_USERNAME`/`PASSWORD` at it.

For each Agent: pre-register it with `POST /api/v1/devices` (`endpoint_id`), get its account
with `POST /api/v1/devices/{id}/mqtt-credentials` and put it into the Agent. Set the
`controller_topic` of the response (`<Controller topic>/<EndpointID>`) as the Agent's
Controller topic (`Device.LocalAgent.Controller.{i}.MTP.{i}.MQTT.Topic`). The broker lets
an Agent write only to its own topic, so Dhonomos knows which Agent a message came from (no
Agent can pose as another). Messages an Agent sends to the shared topic are refused even if
it has an account.

When the Agent runs a WebSocket server (e.g. obuspa
`Device.LocalAgent.MTP.{i}.Protocol "WebSocket"`), turn on `DHONOMOS_USP_WS_CLIENTS=true`
and give `"usp_ws_url": "ws://<agent>:<port>/usp"` at pre-registration; Dhonomos connects
within 30 seconds and reconnects when the connection drops.

On every Agent connection Dhonomos adds subscriptions for Boot!, OperationComplete and
BulkData Push! to the Agent. To keep Dhonomos from writing anything into Agents, set
`DHONOMOS_USP_AUTO_SUBSCRIBE=false`. Features that rely on these notifications (boot time,
`1 BOOT` presets, completion of asynchronous commands) then stop working; read section 4f of
the operations guide first.

### WebSocket MTP (Agents connect to Dhonomos)

Agents connect to `wss://<server>:7549/usp?eid=<EndpointID>` (subprotocol `v1.usp`). In
production, turn it on with TLS and **Agent client certificates required**:

```bash
DHONOMOS_USP_WS_LISTEN=0.0.0.0:7549
DHONOMOS_USP_WS_TLS=true
DHONOMOS_USP_CA_DIR=/var/lib/dhonomos/usp-ca      # USP CA: issues the server and Agent certificates
# DHONOMOS_USP_CA_NAME="Example USP CA"            # optional: CA certificate name (CN), used only when the CA is created
DHONOMOS_USP_WS_CLIENT_CERT=required              # recommended in production: none | optional (default) | required
# Trust a vendor factory CA too: DHONOMOS_USP_WS_CLIENT_CA=/etc/dhonomos/vendor-ca.pem
```

The first use of `DHONOMOS_USP_CA_DIR` creates a CA (`ca.pem`, `ca.key`) in that directory.
Its name (CN) is `DHONOMOS_USP_CA_NAME` (`--usp-ca-name`, up to 64 characters), by default
`Dhonomos USP CA <8 random hex digits>`, so two installations never share a CA name. The
name is used **only when the CA is created**: an existing CA keeps its name (a different value
logs INFO `the existing USP CA keeps its name`). **Do not copy the CA directory between
installations.** The client certificates for devices are issued by this CA (operations guide,
section 4d-1).

`?eid=` is only what the Agent claims. Without client certificates any client can connect
with any EndpointID and pose as that Agent (receiving the tasks meant for it, including
decrypted secrets). **So use `DHONOMOS_USP_WS_CLIENT_CERT=required` in production.** The
default `optional` checks `?eid=` against the EndpointID in the certificate's SAN when a
certificate is presented, and accepts connections without one.

- On a non-loopback address Dhonomos refuses to start unless both TLS and `required` are set
  (the error points to `--usp-ws-client-cert required` and `--usp-ws-allow-anonymous`). A lab
  that must accept Agents without certificates sets `DHONOMOS_USP_WS_ALLOW_ANONYMOUS=true`;
  Dhonomos then starts and logs the warning
  `WebSocket MTP takes Agents without a client certificate`. Off loopback (where a TLS proxy
  would sit in front), plain `ws://` also needs this flag.
- A connection without a certificate cannot replace an open connection of the same
  EndpointID that has one (HTTP 409). A connection with a certificate replaces any connection
  (reconnects, certificate renewals). Refusals are counted in
  `dhonomos_usp_ws_rejected_total`. The built-in MQTT broker and STOMP follow the same rules
  (CONNACK 0x87, ERROR frame).
- **An EndpointID with an issued certificate is refused on every MTP without a certificate**
  (WebSocket 403, STOMP ERROR frame, MQTT CONNACK 0x87 Not authorized). Issuing a certificate
  with `POST /api/v1/devices/{id}/certificate` (any certificate not revoked binds the
  EndpointID) tells all MTPs within 10 seconds. Without this, a holder of the shared STOMP or
  MQTT account (or a plain connection) could claim the EndpointID of a device with a
  certificate, move it to a weaker MTP and receive its tasks, decrypted secrets included.
  Connections already open are not closed (the certificate may be in the middle of being
  installed over them). A device that disconnects before its certificate is installed cannot
  come back with the shared account; so issue the certificate when you are ready to install it,
  or, in a hurry, revoke it to release the device. Expiry does not release it: an expired
  certificate binds the EndpointID until it is revoked.
- A **revoked certificate**
  (`POST /api/v1/devices/{id}/certificates/{cert}/revoke`) is refused on wss, TLS STOMP and
  the TLS built-in MQTT broker (`the client certificate is revoked`), and connections opened
  with it are closed within 10 seconds.
- An external MQTT broker is outside these rules: the broker ends TLS, so the Controller
  never sees the client certificate. There, identity is protected by the broker's per-device
  accounts and topic ACLs (dynamic-security above). A Record sent to the Controller topic that
  all Agents share carries only the sender's own claim of identity, so the Controller always
  ranks that reply address below addresses whose identity an MTP vouches for (connections
  Dhonomos received, per-device topics).
- `eid` is checked by the same rules as on the MQTT broker and STOMP: not empty, at most 256
  bytes, no whitespace, control characters, `+`, `#` or `/`; otherwise 400.
- The Controller connecting to an Agent's WebSocket server (`DHONOMOS_USP_WS_CLIENTS`, above)
  is independent of these settings.

### Built-in MQTT broker

Agents connect straight to Dhonomos over MQTT 5.0, no external broker. With a shared
first-contact account and the onboarding policy (`--onboarding`, `--allowed-oui`) it accepts
devices that were not pre-registered, like CWMP. It can run together with the external broker
mode.

```bash
DHONOMOS_USP_MQTT_BROKER_LISTEN=0.0.0.0:1883
DHONOMOS_USP_MQTT_BROKER_USERNAME=cpe
DHONOMOS_USP_MQTT_BROKER_PASSWORD=<shared password>
# TLS (8883): DHONOMOS_USP_MQTT_BROKER_LISTEN=0.0.0.0:8883 DHONOMOS_USP_MQTT_BROKER_TLS=true
#   certificate as for wss (--usp-ws-tls-cert/key, or issued and renewed by the USP CA of --usp-ca-dir)
# optional: DHONOMOS_USP_MQTT_BROKER_CONTROLLER_TOPIC=usp/controller/dhonomos
#           DHONOMOS_USP_MQTT_BROKER_AGENT_TOPIC_PREFIX=usp/agent/
```

Opening it on a non-loopback address without an account needs
`DHONOMOS_USP_MQTT_BROKER_ALLOW_ANONYMOUS=true` (otherwise Dhonomos refuses to start; labs
only). With a shared account on a non-loopback address without TLS, the account travels in
clear text, and the log warns
`the MQTT broker checks a shared account on a network address without TLS` (the STOMP broker
too). In production use TLS (8883) and client certificates.

Agent settings: transport MQTT, host and port, the username and password above, Controller
EID (default `self::dhonomos-controller`), Controller topic `usp/controller/dhonomos`.
**Leave the Agent topic empty or set it to `usp/agent/<EndpointID>`.** When it is empty, the
Agent must ask for Response Information in its CONNECT (obuspa:
`Device.MQTT.Client.{i}.RequestResponseInfo true`): the broker tells the Agent its topic
(`usp/agent/<EndpointID>`) in the CONNACK Response Information and `subscribe-topic`, and the
Agent subscribes to it and sends its MQTTConnectRecord. With neither, obuspa sends no
MQTTConnectRecord and Dhonomos cannot recognise the Agent.

In short:

- The Agent's EndpointID comes from the SAN of its TLS client certificate, else from the
  `usp-endpoint-id` user property of CONNECT (TR-369 MQTT 5.0 Agents always send it), else
  from the `from_id` of its first Record. With the shared account `usp-endpoint-id` is an
  unauthenticated claim, so use device certificates (from the same USP CA as wss) in
  production. A new connection with the same EndpointID ends the older one with DISCONNECT
  0x8E: two devices with the same EID keep disconnecting each other.
- Agents may write only to the Controller topic (or `<Controller topic>/<EndpointID>`).
  Wildcard and shared subscriptions, QoS 2 and retained messages are refused. Messages are not
  stored: tasks for an Agent that is not connected go out at its next connection.
- The Controller knows at once when a connection ends (socket closed, no answer for 1.5 times
  the Keep Alive). The last contact time (`last_contact_at`) is the last time anything was
  received on that connection.
- MQTT 3.1.1 clients are not accepted yet (planned).

Trying it with an obuspa container (`deploy/obuspa/factory_reset_mqtt_broker.txt`):

```bash
# Build the obuspa image once (deploy/obuspa/Dockerfile):
docker compose -f deploy/docker-compose.dev.yml --profile usp build obuspa
# Keep the file with the shared password unreadable to other users (no /tmp file with the default umask).
d=$(mktemp -d)   # 0700
sed 's/"PASSWORD"/"<shared password>"/' deploy/obuspa/factory_reset_mqtt_broker.txt \
  | install -m 600 /dev/stdin "$d/factory_reset.txt"
docker run --rm --network host -v "$d/factory_reset.txt:/etc/obuspa/factory_reset.txt:ro" \
  dhonomos-dev/obuspa:v11.0.7 -p -v4 -r /etc/obuspa/factory_reset.txt -f /tmp/usp.db -i lo
rm -rf "$d"
```

Run it on the Dhonomos host with `--network host` and match `BrokerAddress`/`BrokerPort` in
the file (default `127.0.0.1:1883`). For TLS add `TransportProtocol "TLS"`, port 8883 and
`-t <ca.pem of the USP CA>`. Success looks like `response_information_topic` and
`subscribe-topic` in the obuspa log's `CONNACK`, then
`agent connected ... reply_to=mqtt:<EndpointID>` in the Dhonomos log. After `docker kill`
of the container, `agent disconnected (MTP closed)` appears within tens of milliseconds.

## 7. WireGuard hub (optional)

A separate program, `dhonomos-wg-hub`, runs the hub that operator PCs and CPEs connect to over
WireGuard. It can run on the Dhonomos host or on another host, and needs no Docker. Run it as
a systemd service on a Linux host with a public address (or a UDP port forward).

You need:

- the `wireguard` kernel module and the `nft` program (package `nftables`);
- outgoing connections from the hub host to the Dhonomos API (HTTPS);
- incoming connections to the hub's UDP ports (one per network, from 51820).

1. On the server (admin):
   - Create a hub: `POST /api/v1/wireguard/hubs` `{"name": "hub1", "endpoint_host": "<public address or name>"}`
   - Issue a hub token: `POST /api/v1/wireguard/hubs/{id}/token`. The `token` in the response
     is shown only this once.
   - Create a network: `POST /api/v1/wireguard/networks` `{"hub_id": …, "name": …}`
2. On the hub host (root):

```bash
install -m 755 dhonomos-wg-hub /usr/local/bin/
install -d -m 700 /etc/dhonomos
install -m 600 /dev/stdin /etc/dhonomos/wg-hub.token   # paste the token, then Ctrl-D
install -m 600 deploy/dhonomos-wg-hub.env.example /etc/dhonomos/wg-hub.env   # edit DHONOMOS_WG_HUB_SERVER
install -m 644 deploy/dhonomos-wg-hub.service /etc/systemd/system/
install -m 644 deploy/99-dhonomos-wg-hub.conf /etc/sysctl.d/ && sysctl --system   # net.ipv4.ip_forward=1
echo wireguard > /etc/modules-load.d/wireguard.conf && modprobe wireguard
systemctl daemon-reload && systemctl enable --now dhonomos-wg-hub
```

3. Firewall:
   - Open the hub's UDP ports, e.g. with ufw: `ufw allow 51820/udp`.
   - Allow forwarding between `dwg` interfaces. The hub's nft table `inet dhonomos_wg` cannot
     undo a drop in another table. On a host with Docker the FORWARD policy is DROP, so
     `iptables -I DOCKER-USER -i dwg+ -o dwg+ -j ACCEPT` is needed. The rule is gone after a
     reboot; add it again after Docker starts.
4. Check:
   - `journalctl -u dhonomos-wg-hub` shows `hub state received`.
   - `GET /api/v1/wireguard/hubs/{id}` has `public_key`, `last_seen_at` and `version` filled
     in.
   - `ip link show type wireguard` shows `dwg<port>`.
   - `--dry-run` prints what would change and changes nothing; use it on the first install.

When the hub stops or cannot reach the server, the kernel state (the tunnels) stays as it is.
To remove the hub for good, delete the `dwg*` links, the `iif dwg*` rule with priority 10000
and `table inet dhonomos_wg`.

## 8. Operations notes

Backup, upgrade, monitoring and troubleshooting: [operations guide](operations.md) (Korean).

- Health: `GET /healthz`; metrics: `GET /metrics` (viewer or higher).
- Backup: PostgreSQL (`pg_dump`) and the file volume (`files`) together.
- With HTTPS webhooks, mount the host's CA bundle (included in the compose example).
- Upgrade: replace the image; database migrations run at start.
- Connection Request targets: loopback, link-local (including the 169.254.169.254 metadata
  address) and multicast are blocked by default. Block the server network of the ACS and
  similar with `DHONOMOS_CR_DENY`; if the CPE ranges are known, allow only them with
  `DHONOMOS_CR_ALLOW`.
- Retention: events 30 days, finished tasks and cleared alarms 90 days, time series 30 days
  by default (`DHONOMOS_*_RETENTION_DAYS`, 0 = keep forever).
