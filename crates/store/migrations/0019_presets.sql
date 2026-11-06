-- Provisioning presets managed through the API and UI (UI-03, ADR-077), instead of the
-- YAML file (`--presets`, still supported). `definition` is the preset as in the file
-- (name, when, once, priority, run, script_source, args).
CREATE TABLE presets (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    name        text NOT NULL,
    enabled     boolean NOT NULL DEFAULT true,
    definition  jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
    revision    integer NOT NULL DEFAULT 1,
    updated_by  text,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

-- Every saved revision and deletion (definition NULL), for the history view.
CREATE TABLE preset_history (
    id          bigserial PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    name        text NOT NULL,
    revision    integer NOT NULL,
    enabled     boolean NOT NULL,
    definition  jsonb,
    changed_by  text,
    changed_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX preset_history_name ON preset_history (tenant_id, name, id DESC);

-- Bumped with every change of a kind of configuration, so every process notices and
-- reloads (`presets`).
CREATE TABLE config_revisions (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    kind       text NOT NULL,
    revision   bigint NOT NULL,
    PRIMARY KEY (tenant_id, kind)
);
