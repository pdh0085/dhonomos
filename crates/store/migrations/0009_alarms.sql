-- Alarms (CO-07): raised and cleared by rules; one active alarm per device and rule.
CREATE TABLE alarms (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    device_id   uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    rule        text NOT NULL,
    severity    text NOT NULL CHECK (severity IN ('critical', 'major', 'minor', 'warning')),
    state       text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'cleared')),
    message     text NOT NULL,
    detail      jsonb NOT NULL DEFAULT '{}',
    raised_at   timestamptz NOT NULL DEFAULT now(),
    cleared_at  timestamptz,
    acked_at    timestamptz,
    acked_by    text
);

CREATE UNIQUE INDEX alarms_one_active ON alarms (device_id, rule) WHERE state = 'active';
CREATE INDEX alarms_by_state ON alarms (tenant_id, state, raised_at DESC);
