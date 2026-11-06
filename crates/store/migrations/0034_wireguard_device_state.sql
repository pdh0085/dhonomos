-- WireGuard stage 4 (ADR-110, docs/design/13-wireguard.md §6.1): the server configures a
-- device member's CPE itself (TR-181 `Device.WireGuard.` over CWMP) and keeps how the last
-- run on the device went, per member:
--
-- - `device_state`: `pending` (not run yet, or the desired state changed), `applied`,
--   `blocked` (the device cannot take it as it is, see `device_detail`), `unsupported` (no
--   `Device.WireGuard.`), `error` (a fault or no progress, see `device_detail`). Device
--   members only.
-- - `device_checked_at`: when a run last recorded a state.
-- - `device_applied_hash`: the desired state (`dhonomos_wireguard::desired_hash`) of the last
--   run: what was applied, or what was tried when the run ended otherwise. A different hash
--   starts a new run.
--
-- These change on every run. Member updates bump the hub's state revision (0032), which
-- would wake the hub's long-poll each time: from now on an UPDATE bumps only when a column
-- the hub's state is made of changed.

ALTER TABLE wg_members
    ADD COLUMN device_state text
        CHECK (device_state IN ('pending', 'applied', 'blocked', 'unsupported', 'error')),
    ADD COLUMN device_detail text,
    ADD COLUMN device_checked_at timestamptz,
    ADD COLUMN device_applied_hash text;

UPDATE wg_members SET device_state = 'pending' WHERE kind = 'device';

ALTER TABLE wg_members
    ADD CONSTRAINT wg_members_device_state CHECK ((kind = 'device') = (device_state IS NOT NULL));

CREATE OR REPLACE FUNCTION wg_members_bump() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    hubs uuid[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        hubs := array(SELECT DISTINCT n.hub_id
                      FROM new_rows m JOIN wg_networks n ON n.id = m.network_id);
    ELSIF TG_OP = 'UPDATE' THEN
        -- Only rows where something the hub sees changed.
        hubs := array(WITH changed AS (
                          SELECT nm.network_id AS new_network, om.network_id AS old_network
                          FROM new_rows nm JOIN old_rows om ON om.id = nm.id
                          WHERE (nm.network_id, nm.kind, nm.public_key, nm.revoked_at, nm.address)
                                IS DISTINCT FROM
                                (om.network_id, om.kind, om.public_key, om.revoked_at, om.address)
                      )
                      SELECT n.hub_id FROM changed c JOIN wg_networks n ON n.id = c.new_network
                      UNION
                      SELECT n.hub_id FROM changed c JOIN wg_networks n ON n.id = c.old_network);
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
