-- How far the audit log has been shipped to each external sink (ADR-083).
CREATE TABLE audit_export (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    sink        text NOT NULL,
    last_id     bigint NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, sink)
);
