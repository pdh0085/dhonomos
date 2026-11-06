-- Supported data model per firmware (US-11): one row per device fingerprint
-- (manufacturer, OUI, product class, model, software version), shared by devices.
CREATE TABLE supported_models (
    id           uuid PRIMARY KEY,
    fingerprint  text NOT NULL UNIQUE,
    protocol     text NOT NULL CHECK (protocol IN ('cwmp', 'usp')),
    model        jsonb NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE devices
    ADD COLUMN supported_model_id uuid REFERENCES supported_models (id) ON DELETE SET NULL;
