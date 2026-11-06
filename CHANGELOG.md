# Changelog

All notable changes to Dhonomos. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

First development line: a CWMP (TR-069) ACS and USP (TR-369) Controller in one binary.

### CWMP ACS
- TR-069 Amendment 6 sessions (CWMP 1.0–1.4), TLS, Digest/Basic and per-device credentials.
- Zero-touch: full parameter and name read of new devices; onboarding policies (auto,
  quarantine, pre-registered, OUI allow-list).
- Connection Requests over HTTP and UDP (built-in STUN with MESSAGE-INTEGRITY), and over XMPP
  (TR-069 Annex K) for CPEs behind NAT or CGNAT: a built-in XMPP server (`--xmpp-listen`,
  STARTTLS required, SASL PLAIN, one account and password per device that zero-touch sets up
  on TR-181 CPEs) takes the connection the CPE opens, the Connection Request goes over it and
  the CPE's answer confirms delivery. A device with an XMPP session is woken over XMPP first.
- Downloads from the built-in file server (signed links) with bandwidth and parallel download
  limits and a per-download log (bytes, duration, complete); uploads of vendor configuration files.
- gzip and deflate request bodies (`Content-Encoding`), capped at 8 MiB once decompressed;
  other encodings are refused with 415.
- 2,000 Informs/s with 50,000 CPEs in 113 MB.

### USP Controller
- MTPs: MQTT 5 (through an external broker, or straight to a broker embedded in Dhonomos),
  WebSocket (ws/wss, Agents connecting in or the Controller connecting out
  to Agents that run a WebSocket server) and STOMP 1.2 with a broker embedded in Dhonomos
  (Agents connect straight to it with a shared first-contact login; no external broker),
  several per Agent with fallback.
- Embedded MQTT 5.0 broker (`--usp-mqtt-broker-listen`, TLS with `--usp-mqtt-broker-tls`): a
  shared first-contact account and the onboarding policy let unregistered Agents in like
  CWMP devices; the Agent's EndpointID comes from its client certificate, the
  `usp-endpoint-id` CONNECT property or its first Record; it is told its topic in the CONNACK
  (`subscribe-topic`, Response Information); Agents may only publish to the Controller topic,
  and their disconnection (socket closed, Keep Alive missed) is known at once. Only what USP
  needs: no wildcard or shared subscriptions, QoS 2, retained messages or stored sessions.
  MQTT 3.1.1 is refused for now.
- TLS (and mutual TLS) to the MQTT broker (`--usp-mqtt-tls`).
- MQTT Agents publish to their own Controller topic (`<topic>/<EndpointID>`, enforced by the
  broker); Records whose `from_id` differs from the vouched sender are dropped.
- Security headers and a hash-based Content Security Policy for the UI; cross-origin change
  requests refused for cookie sessions; the last admin cannot be removed; an API without
  accounts refuses to listen on a network address unless `--api-allow-open`.
- Broker accounts per Agent (Mosquitto dynamic-security), own CA and Agent certificates with
  an issue history, an expiring list and revocation (refused and disconnected on wss, on
  STOMP over TLS and on the embedded MQTT broker); vendor factory CAs can be trusted too
  (`--usp-ws-client-ca`). An EndpointID with a certificate issued is refused to connections
  without one on every MTP Dhonomos serves, so a shared STOMP or MQTT login cannot take the
  place of an Agent that proves itself with its certificate.
- A USP Agent's last contact is the last time Dhonomos received anything from its connection
  (any WebSocket frame, any STOMP bytes and, on Linux, TCP acknowledgements, which keep an idle
  STOMP Agent without heart-beat current), not the time the connection was last looked at: a
  device that loses power stops advancing at once instead of until the dead connection is
  noticed. Written when it moved, and once more when the connection closes.
- Supported data model cache per firmware (not used for Agents that report no software
  version; refreshed by hand with `POST /api/v1/devices/{id}/data-model/refresh`),
  subscriptions (`--usp-auto-subscribe=false` keeps the Controller from writing them into
  Agents), Operate, firmware images.
- Request timeouts: `--usp-request-timeout` (30 s) for ordinary requests and
  `--usp-full-read-timeout` (120 s) for reads of the whole data model (a Get that includes
  `Device.`, GetSupportedDM), so that a slow Agent right after boot is not given up on; a
  response that arrives after its request timed out is logged at info level.

### Operations
- Tasks with retries, presets with dry runs, sandboxed Rune provisioning scripts (declare,
  then commit only what differs; traced per run) and virtual parameters, bulk jobs and firmware campaigns (canary
  stages, gates, automatic pause, version verification).
- Diagnostics with one result shape for CWMP and USP (ping, traceroute, DNS, TR-143,
  Wi-Fi neighbours); Wi-Fi view.
- Time series from BulkData (HTTP and USP) with compaction; alarms with signed webhooks;
  server-sent events.
- Device attributes for subscriber links (subscriber number, PPPoE account, line ID...):
  edit, CSV import, search, and use in presets, scripts, jobs and alarm rules.
- Configuration backups, drift, restore, device replacement and deletion; vendor
  configuration file backup and restore for CWMP and USP (`VendorConfigFile` Backup/Restore).
- Accounts, sessions, API keys and roles; OpenID Connect single sign-on with group-to-role
  mapping; audit log with filters (actor, action prefix, target, time) and paging, shipped
  in order to a webhook (`--audit-webhook-url`).
- Two-factor authentication (TOTP, RFC 6238) for local accounts, required for the roles in
  `--require-totp-roles` (admin by default, `admin,operator` on the internet;
  `--require-admin-totp` still works; needs `--secrets-key`) and optional for other roles:
  QR enrollment in the web UI, single-use recovery codes, codes accepted once, an admin can
  reset a user who lost the phone. API keys, `--api-token` and single sign-on are not asked.
- Publishing the web UI behind a TLS reverse proxy on the same host: open mode (no accounts)
  is never granted to a request that went through a proxy; `--trusted-proxies` names the
  proxies whose `X-Forwarded-For` / `Forwarded` / `X-Forwarded-Proto` / `X-Forwarded-Host`
  are believed, so rate limits, lockouts and logs see each visitor; `--public-url` makes the
  cross-site request check exact; login attempts are counted before they are checked, per
  name and client address (5 per 15 minutes) and per name over all addresses (50), with the
  two-factor screens in a table of their own; `--session-idle-minutes` (default 60) ends unused
  sessions; with `--secure-cookies` the session cookie is `__Host-` prefixed; single sign-on
  and the UI refuse return paths that could leave the site; every response without its own
  cache policy is `no-store`; a preset's masked secret is kept only while the task still sends
  it to the same place (ADR-103).
- Refused connections and requests are logged at info with the source address, the listener
  and a short reason (`connection refused` / `request refused` `listener=… remote=… reason=…`,
  plus the username tried for failed logins), for the ACS, file server, XMPP, USP
  WebSocket/STOMP/MQTT and STUN listeners. Each (listener, reason, source IP) logs once per
  10 minutes and reports the repeats it left out as `suppressed=N`; the Prometheus counters
  are unchanged. `scripts/security-report.sh` turns these lines, the Apache access logs and the
  firewall log into a daily text report with an attention list.
- Device scopes for viewers, operators and API keys (tags, attributes, protocol, OUI,
  product class): devices outside are hidden, jobs and silences are narrowed to the scope.
- OpenAPI 3.1 document of the REST API at `/api/v1/openapi.json`; CSV exports of devices,
  job members and alarms.
- Device filter expressions (`and`/`or`/`not`, device fields, tags, attributes, stored
  parameter values, contact ages) for the device list, CSV exports and job targets.
- Retention for events, finished tasks, cleared alarms and expired sessions.
- OpenTelemetry traces over OTLP/HTTP (`--otlp-endpoint`).
- Connection Request address policy against SSRF (`--cr-allow`, `--cr-deny`).
- HTTPS for the file server (`--files-tls-cert`, `--files-tls-key`); certificates of the
  ACS, file server, wss and STOMP listeners are re-read from their PEM files when they
  change, so renewals need no restart (`dhonomos_tls_reload_total`).
- wss and STOMP certificates issued by the USP CA (`--usp-ca-dir`, no certificate file) are
  issued again 7 days before they expire, with a fresh key, and served to new connections;
  a failed renewal keeps the current certificate and is retried hourly.
- Agent client certificates handed to the device installer: `POST /api/v1/certificates/bundle`
  (and Issue certificates on the device list) generates keys and certificates for up to 1,000
  devices and returns an AES-256 encrypted zip with a `client.pem` per device (certificate,
  then key: the format of `obuspa -a`), `ca.pem` and `manifest.csv`; keys and password are
  never stored. The devices are named by ID, EndpointID, OUI and serial number (EndpointID
  `os::<OUI>-<serial>`) or a filter expression, and need not have connected: Agents that do
  not exist yet are pre-registered together with the certificates, and a CWMP device stands
  for the Agent derived from its OUI and serial number.
- Devices can be added before they connect from a list of EndpointIDs or serial numbers
  (Add devices on the device list, `POST /api/v1/devices/bulk`, up to 10,000 per request,
  with a preview that writes nothing). Single issues default to 1095 days and
  return `client_pem`. `--usp-ca-name` names a new CA (default `Dhonomos USP CA` plus a random
  suffix per installation).
- Devices selected in the list can be deleted together (`POST /api/v1/devices/delete`, up to
  1,000 per request, admins; Delete N devices on the device list): every device is checked
  first and nothing is deleted if one is unknown or, without `retire`, not retired; each is
  then deleted as by `DELETE /devices/{id}` (Agent certificates revoked and kept, uploaded
  files removed) and audited as `device.delete` with a `device.delete_bulk` summary.
- Per-device ACS credentials bound to their device; optionally issued on zero-touch, after
  which the shared credential is refused for that device.
- Per-device Connection Request credentials issued on zero-touch; secret parameter values
  (`"secret": true`) stored encrypted; secrets key rotation (`--secrets-old-keys`).
- Alarm silences (maintenance windows) and storm grouping of webhooks; alarm e-mails
  (SMTP with STARTTLS or TLS).
- Device parameters as a tree grouped by object, with search; writable values are edited in
  place and applied together as one SetParameterValues (CWMP) or Set (USP) with a connection
  request, refusals shown next to each value; objects can be read again (Refresh).
- Task traces: every task records its steps (queued, sent, waiting, retry, succeeded,
  failed, cancelled, expired) with time, attempt and error; the device page shows them with
  the task's arguments, result and origin.
- Presets kept in the database and edited in the UI (conditions, tasks or Rune script,
  revisions with conflict detection, history, test runs of unsaved drafts, YAML import and
  export); a `--presets` file keeps working read-only. Presets and alarm rules from files
  reload on SIGHUP.
- API rate limits per caller (`--api-rate-limit`); sources repeatedly failing CPE
  authentication are blocked for a while (`--cpe-auth-failure-limit`); sessions per CPE are
  capped (`--cpe-session-limit`, fault 8005 beyond it).
- Web UI: overview, device search and details, jobs, presets with dry runs and script traces,
  alarms, files, users and keys.
- Performance regression gate (`cargo xtask bench`) run by the release script.
- Release image on `scratch` (22 MB), compose deployment, SBOM (`cargo xtask sbom`),
  checksums signed with `ssh-keygen -Y` (`scripts/verify-release.sh`).
