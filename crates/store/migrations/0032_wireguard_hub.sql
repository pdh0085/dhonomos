-- WireGuard stage 2 (ADR-110, docs/design/13-wireguard.md): the hub process
-- (`dhonomos-wg-hub`) fetches its desired state from the server, applies it and reports how
-- its peers are doing.
--
-- Hub token: a hub authenticates with a token an admin issues (`dwh_...`). Only its SHA-256
-- is stored, with a short prefix to recognise it by; issuing a new one replaces the old one
-- at once.
--
-- Change tracking: `wg_hubs.state_revision` grows whenever a network, member or site prefix
-- of the hub changes (statement-level triggers below). The hub long-polls with the revision
-- it has and gets the new state as soon as it differs.
--
-- Peer status: what the hub's interfaces report about each peer (endpoint, last handshake,
-- traffic), one row per member, overwritten by every report. Neither it nor the hub's
-- last-seen columns bump the revision.

ALTER TABLE wg_hubs
    ADD COLUMN token_hash bytea UNIQUE
        CHECK (token_hash IS NULL OR length(token_hash) = 32),
    ADD COLUMN token_prefix text,
    ADD COLUMN token_created_at timestamptz,
    ADD COLUMN state_revision bigint NOT NULL DEFAULT 1,
    -- When the hub last called the server, from where, and which version it runs.
    ADD COLUMN last_seen_at timestamptz,
    ADD COLUMN last_seen_ip inet,
    ADD COLUMN hub_version text CHECK (hub_version IS NULL OR length(hub_version) <= 64),
    ADD CONSTRAINT wg_hubs_token_complete
        CHECK ((token_hash IS NULL) = (token_prefix IS NULL)
               AND (token_hash IS NULL) = (token_created_at IS NULL));

-- The latest report of the hub about a member.
CREATE TABLE wg_peer_status (
    member_id         uuid PRIMARY KEY REFERENCES wg_members (id) ON DELETE CASCADE,
    endpoint          text CHECK (endpoint IS NULL OR length(endpoint) <= 64),
    latest_handshake  timestamptz,
    rx_bytes          bigint NOT NULL CHECK (rx_bytes >= 0),
    tx_bytes          bigint NOT NULL CHECK (tx_bytes >= 0),
    reported_at       timestamptz NOT NULL
);

-- Adds 1 to the revision of the given hubs. The rows are locked in id order, so that two
-- transactions bumping overlapping sets of hubs cannot deadlock on each other. `updated_at`
-- stays: it is about the hub's own settings.
CREATE FUNCTION wg_bump_hubs(hubs uuid[]) RETURNS void LANGUAGE sql AS $$
    WITH locked AS (
        SELECT id FROM wg_hubs WHERE id = ANY (hubs) ORDER BY id FOR NO KEY UPDATE
    )
    UPDATE wg_hubs h SET state_revision = h.state_revision + 1
    FROM locked WHERE h.id = locked.id;
$$;

-- The triggers run once per statement, with the changed rows as transition tables
-- (`new_rows`, `old_rows`). PostgreSQL allows transition tables only on a trigger for a
-- single event, hence one trigger per table and event; each function only reads the
-- transition tables its event has. Rows removed by a cascade whose parent is already gone
-- (a network's members, a member's site prefixes) find no hub here: the parent's own trigger
-- has bumped it.

CREATE FUNCTION wg_networks_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    hubs uuid[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        hubs := array(SELECT DISTINCT hub_id FROM new_rows);
    ELSIF TG_OP = 'UPDATE' THEN
        hubs := array(SELECT hub_id FROM new_rows UNION SELECT hub_id FROM old_rows);
    ELSE
        hubs := array(SELECT DISTINCT hub_id FROM old_rows);
    END IF;
    IF cardinality(hubs) > 0 THEN
        PERFORM wg_bump_hubs(hubs);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER wg_networks_bump_insert AFTER INSERT ON wg_networks
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION wg_networks_bump();
CREATE TRIGGER wg_networks_bump_update AFTER UPDATE ON wg_networks
    REFERENCING NEW TABLE AS new_rows OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION wg_networks_bump();
CREATE TRIGGER wg_networks_bump_delete AFTER DELETE ON wg_networks
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION wg_networks_bump();

CREATE FUNCTION wg_members_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    hubs uuid[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        hubs := array(SELECT DISTINCT n.hub_id
                      FROM new_rows m JOIN wg_networks n ON n.id = m.network_id);
    ELSIF TG_OP = 'UPDATE' THEN
        hubs := array(SELECT n.hub_id FROM new_rows m JOIN wg_networks n ON n.id = m.network_id
                      UNION
                      SELECT n.hub_id FROM old_rows m JOIN wg_networks n ON n.id = m.network_id);
    ELSE
        hubs := array(SELECT DISTINCT n.hub_id
                      FROM old_rows m JOIN wg_networks n ON n.id = m.network_id);
    END IF;
    IF cardinality(hubs) > 0 THEN
        PERFORM wg_bump_hubs(hubs);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER wg_members_bump_insert AFTER INSERT ON wg_members
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION wg_members_bump();
CREATE TRIGGER wg_members_bump_update AFTER UPDATE ON wg_members
    REFERENCING NEW TABLE AS new_rows OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION wg_members_bump();
CREATE TRIGGER wg_members_bump_delete AFTER DELETE ON wg_members
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION wg_members_bump();

CREATE FUNCTION wg_site_prefixes_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    hubs uuid[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        hubs := array(SELECT DISTINCT n.hub_id
                      FROM new_rows sp JOIN wg_members m ON m.id = sp.member_id
                      JOIN wg_networks n ON n.id = m.network_id);
    ELSIF TG_OP = 'UPDATE' THEN
        hubs := array(SELECT n.hub_id
                      FROM new_rows sp JOIN wg_members m ON m.id = sp.member_id
                      JOIN wg_networks n ON n.id = m.network_id
                      UNION
                      SELECT n.hub_id
                      FROM old_rows sp JOIN wg_members m ON m.id = sp.member_id
                      JOIN wg_networks n ON n.id = m.network_id);
    ELSE
        hubs := array(SELECT DISTINCT n.hub_id
                      FROM old_rows sp JOIN wg_members m ON m.id = sp.member_id
                      JOIN wg_networks n ON n.id = m.network_id);
    END IF;
    IF cardinality(hubs) > 0 THEN
        PERFORM wg_bump_hubs(hubs);
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER wg_site_prefixes_bump_insert AFTER INSERT ON wg_site_prefixes
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION wg_site_prefixes_bump();
CREATE TRIGGER wg_site_prefixes_bump_update AFTER UPDATE ON wg_site_prefixes
    REFERENCING NEW TABLE AS new_rows OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION wg_site_prefixes_bump();
CREATE TRIGGER wg_site_prefixes_bump_delete AFTER DELETE ON wg_site_prefixes
    REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION wg_site_prefixes_bump();

-- No trigger on wg_hubs itself or on wg_peer_status: a hub's last-seen columns and its status
-- reports change on every call and must not wake the hub's own long-poll.
