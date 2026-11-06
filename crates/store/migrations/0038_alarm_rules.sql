-- Alarm rules edited from the web (runtime settings, stage 4): one YAML rule set per
-- tenant, as an `--alarms` file would hold it. Used only when the server runs without
-- `--alarms`; the file always wins.
CREATE TABLE alarm_rule_sets (
    tenant_id   uuid PRIMARY KEY REFERENCES tenants (id),
    yaml        text NOT NULL,
    updated_by  text,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Every version stored, for the history view (`yaml` NULL: the rules were removed).
CREATE TABLE alarm_rule_set_history (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    yaml       text,
    actor      text,
    at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX alarm_rule_set_history_tenant ON alarm_rule_set_history (tenant_id, id DESC);
