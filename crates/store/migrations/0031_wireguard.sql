-- WireGuard management (ADR-110, docs/design/13-wireguard.md): hubs, overlay networks, their
-- members and the LAN prefixes behind device members. Stage 1 keeps the data and serves it
-- through the API; the hub process and the CPE provisioning read it in later stages.
--
-- Addresses are PostgreSQL `inet` (members) and `cidr` (prefixes), so the database refuses
-- malformed and non-canonical values itself. The server reads and writes them as text
-- (`host(address)`, `prefix::text`) and does the allocation in Rust (dhonomos-wireguard).
--
-- No private key is stored anywhere: only public keys (ADR-110 Q7).

-- A WireGuard endpoint Dhonomos manages. `public_key` is filled by the hub process (stage
-- 2) once it has made its key pair; `endpoint_host` is what members dial.
CREATE TABLE wg_hubs (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    name           text NOT NULL,
    endpoint_host  text NOT NULL,
    public_key     text CHECK (public_key IS NULL OR length(public_key) = 44),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    -- The target of the composite key below: a network and its hub share a tenant.
    UNIQUE (id, tenant_id)
);

-- One overlay: a tunnel prefix and one hub interface. The hub's own address is the first
-- host of `ipv4_prefix` (.1). Networks of a tenant never overlap (checked by the server
-- under a lock, in dhonomos-wireguard).
CREATE TABLE wg_networks (
    id                     uuid PRIMARY KEY,
    tenant_id              uuid NOT NULL REFERENCES tenants (id),
    hub_id                 uuid NOT NULL,
    name                   text NOT NULL,
    ipv4_prefix            cidr NOT NULL
                           CHECK (family(ipv4_prefix) = 4 AND masklen(ipv4_prefix) BETWEEN 16 AND 29),
    listen_port            integer NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
    mtu                    integer NOT NULL DEFAULT 1420 CHECK (mtu BETWEEN 1280 AND 1500),
    persistent_keepalive   integer NOT NULL DEFAULT 25
                           CHECK (persistent_keepalive BETWEEN 0 AND 65535),
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    -- One UDP port per hub interface.
    UNIQUE (hub_id, listen_port),
    FOREIGN KEY (hub_id, tenant_id) REFERENCES wg_hubs (id, tenant_id) ON DELETE RESTRICT
);

-- A peer of a network: a CPE (`device`, configured over TR-181) or an operator PC or server
-- (`client`, handed a configuration file). A revoked member keeps its row for the audit
-- trail; the live-member indexes below let its address, key and device be used again, and
-- the server gives an address out again only after the reuse delay
-- (`--wg-address-reuse-delay-hours`).
CREATE TABLE wg_members (
    id                      uuid PRIMARY KEY,
    network_id              uuid NOT NULL REFERENCES wg_networks (id) ON DELETE CASCADE,
    kind                    text NOT NULL CHECK (kind IN ('device', 'client')),
    -- Device members only. Deleting the device removes the member.
    device_id               uuid REFERENCES devices (id) ON DELETE CASCADE,
    -- The account a client belongs to; NULL for a server client made by an admin. When the
    -- account is deleted its clients are revoked first and keep their row (SET NULL).
    user_id                 uuid REFERENCES users (id) ON DELETE SET NULL,
    name                    text NOT NULL,
    -- NULL only for a device member whose key is not known yet (the device makes it, or the
    -- server sends one, in stage 4).
    public_key              text CHECK (public_key IS NULL OR length(public_key) = 44),
    -- Device members: where the key is made (`device`: on the CPE, read back; `server`:
    -- made by Dhonomos and sent, never stored).
    key_mode                text CHECK (key_mode IN ('device', 'server')),
    preshared_key_enabled   boolean NOT NULL DEFAULT false,
    address                 inet NOT NULL CHECK (family(address) = 4 AND masklen(address) = 32),
    revoked_at              timestamptz,
    revoked_reason          text,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    CHECK ((kind = 'device') = (device_id IS NOT NULL)),
    CHECK ((kind = 'device') = (key_mode IS NOT NULL)),
    CHECK (kind = 'client' OR user_id IS NULL),
    CHECK (kind = 'device' OR public_key IS NOT NULL),
    CHECK (revoked_reason IS NULL OR revoked_at IS NOT NULL)
);

CREATE UNIQUE INDEX wg_members_live_address ON wg_members (network_id, address)
    WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX wg_members_live_device ON wg_members (network_id, device_id)
    WHERE revoked_at IS NULL AND device_id IS NOT NULL;
CREATE UNIQUE INDEX wg_members_live_key ON wg_members (network_id, public_key)
    WHERE revoked_at IS NULL AND public_key IS NOT NULL;
CREATE INDEX wg_members_network ON wg_members (network_id);
CREATE INDEX wg_members_device ON wg_members (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX wg_members_user ON wg_members (user_id) WHERE user_id IS NOT NULL;

-- The LAN prefixes behind a device member (design 13 §4). They must not overlap each other
-- or the network's tunnel prefix within one network; the server checks that under a lock
-- because it spans rows.
CREATE TABLE wg_site_prefixes (
    id           uuid PRIMARY KEY,
    member_id    uuid NOT NULL REFERENCES wg_members (id) ON DELETE CASCADE,
    prefix       cidr NOT NULL CHECK (family(prefix) = 4),
    description  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (member_id, prefix)
);
