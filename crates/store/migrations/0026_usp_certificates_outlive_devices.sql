-- An Agent certificate stays cryptographically valid (up to three years) after its device is
-- deleted, so its row must outlive the device: it is what keeps the certificate in the revoked
-- set the MTPs enforce (ADR-080/098) and what an operator can still revoke. Deleting a device
-- now revokes its certificates first (`Store::delete_device`) and the rows stay behind with
-- `device_id` NULL, where `ON DELETE CASCADE` used to remove them.
--
-- The EndpointID is kept on the row, so that a row without a device still says whom the
-- certificate was for and the EndpointIDs bound to certificates no longer depend on the
-- device row (ADR-098).
ALTER TABLE usp_certificates ADD COLUMN endpoint_id text;
UPDATE usp_certificates c SET endpoint_id = d.endpoint_id
FROM devices d
WHERE d.id = c.device_id AND d.protocol = 'usp';

ALTER TABLE usp_certificates
    ALTER COLUMN device_id DROP NOT NULL,
    DROP CONSTRAINT usp_certificates_device_id_fkey,
    ADD CONSTRAINT usp_certificates_device_id_fkey
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL;

-- A certificate whose record was lost is revoked by its fingerprint alone
-- (`POST /certificates/revoke`): the serial number and the expiry may then be unknown (an
-- unknown expiry is treated as never expiring). A row tied to a device always has both.
ALTER TABLE usp_certificates
    ALTER COLUMN serial DROP NOT NULL,
    ALTER COLUMN not_after DROP NOT NULL,
    ADD CONSTRAINT usp_certificates_known_check
        CHECK (device_id IS NULL OR (serial IS NOT NULL AND not_after IS NOT NULL));

-- One row per certificate: revoking by fingerprint finds or inserts it atomically.
CREATE UNIQUE INDEX usp_certificates_fingerprint ON usp_certificates (tenant_id, fingerprint);
