-- Runtime settings changed from the web (runtime settings, stages 2-3): one raw value per
-- server option, as an environment variable or the command line would carry it (a JSON
-- string, or an array of strings for options that take several values). A value given in
-- the server's own configuration always wins over the one stored here.
CREATE TABLE runtime_settings (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    key         text NOT NULL,
    value       jsonb NOT NULL,
    updated_by  text,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key)
);

-- Every change, for the history view: `new` NULL is a reset to the default, `old` NULL a
-- first value.
CREATE TABLE runtime_settings_history (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    key        text NOT NULL,
    old        jsonb,
    new        jsonb,
    actor      text,
    at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX runtime_settings_history_key ON runtime_settings_history (tenant_id, key, id DESC);
