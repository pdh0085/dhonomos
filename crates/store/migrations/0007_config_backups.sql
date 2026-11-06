-- Configuration backups (CO-08): writable parameter values captured from the snapshot,
-- restorable onto the same or a replacement device (CO-14).
CREATE TABLE config_backups (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    label       text NOT NULL DEFAULT '',
    params      jsonb NOT NULL,
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX config_backups_device ON config_backups (device_id, created_at DESC);
