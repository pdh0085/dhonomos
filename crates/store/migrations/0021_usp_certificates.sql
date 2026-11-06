-- Certificates the USP CA issued to Agents (US-08/US-18, ADR-080): for listing, expiry
-- tracking and revocation. Only public facts are kept; private keys never are.
CREATE TABLE usp_certificates (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    device_id      uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    serial         text NOT NULL,
    fingerprint    text NOT NULL,          -- SHA-256 of the DER certificate, hex
    not_after      timestamptz NOT NULL,
    from_csr       boolean NOT NULL,
    issued_by      text,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at     timestamptz,
    revoked_by     text,
    revoke_reason  text,
    UNIQUE (tenant_id, serial)
);

CREATE INDEX usp_certificates_device ON usp_certificates (device_id, issued_at DESC);
CREATE INDEX usp_certificates_expiry ON usp_certificates (tenant_id, not_after)
    WHERE revoked_at IS NULL;
