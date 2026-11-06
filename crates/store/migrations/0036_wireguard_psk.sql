-- WireGuard pre-shared keys (ADR-110, docs/design/13-wireguard.md): a member with
-- `preshared_key_enabled` has a 32-byte random key the server made, shared by the hub and the
-- member. Unlike private keys it is stored, because the hub needs it again after a restart
-- and a device after a factory reset: sealed with the server's secrets key (`--secrets-key`,
-- AES-256-GCM, bound to the member's ID).
--
-- - `psk_ciphertext`, `psk_nonce`: the sealed key; both null or both set, and set exactly
--   when `preshared_key_enabled`.
--
-- A changed key bumps the hub's state revision (0034): `psk_ciphertext` joins the columns
-- the hub's state is made of.

ALTER TABLE wg_members
    ADD COLUMN psk_ciphertext bytea,
    ADD COLUMN psk_nonce bytea;

UPDATE wg_members SET preshared_key_enabled = false WHERE psk_ciphertext IS NULL;

ALTER TABLE wg_members
    ADD CONSTRAINT wg_members_psk_pair CHECK ((psk_ciphertext IS NULL) = (psk_nonce IS NULL)),
    ADD CONSTRAINT wg_members_psk_enabled CHECK (preshared_key_enabled = (psk_ciphertext IS NOT NULL));

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
                          WHERE (nm.network_id, nm.kind, nm.public_key, nm.revoked_at, nm.address,
                                 nm.psk_ciphertext)
                                IS DISTINCT FROM
                                (om.network_id, om.kind, om.public_key, om.revoked_at, om.address,
                                 om.psk_ciphertext)
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
