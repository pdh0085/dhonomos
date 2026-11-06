-- Alarm silences (maintenance windows): matching alarms are still recorded but not notified.
CREATE TABLE alarm_silences (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    rule        text,                          -- NULL: every rule
    devices     jsonb NOT NULL DEFAULT '{}',   -- device filter, as in jobs
    starts_at   timestamptz NOT NULL,
    ends_at     timestamptz NOT NULL,
    comment     text NOT NULL DEFAULT '',
    created_by  text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (ends_at > starts_at)
);

CREATE INDEX alarm_silences_by_end ON alarm_silences (tenant_id, ends_at);

-- The silence an alarm was raised under (no foreign key: the record outlives the silence).
ALTER TABLE alarms ADD COLUMN silenced_by uuid;
