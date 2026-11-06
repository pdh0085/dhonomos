-- WireGuard device key rotation (ADR-110, docs/design/13-wireguard.md §7): an operator asks
-- for a device member's key to be replaced, and the next run on the device makes the CPE use
-- a new key (server key mode: a new server-made key pair; device key mode: the CPE makes one
-- when its PrivateKey is set to ""). The swap is direct: the new public key is stored as the
-- member's, and the hub replaces the peer.
--
-- - `rotate_requested_at`: when the rotation was asked for; cleared once a run applied the
--   member with a key that really changed. Device members only.
--
-- The hub's state revision (0034) bumps only when the public key changes, not for this
-- column.

ALTER TABLE wg_members
    ADD COLUMN rotate_requested_at timestamptz;

ALTER TABLE wg_members
    ADD CONSTRAINT wg_members_rotate_device CHECK (kind = 'device' OR rotate_requested_at IS NULL);
