-- Per-device ACS credentials (CO-16): `acs_auth_pending` while being set on the CPE, and
-- when the CPE first authenticated with its own credential (after that, shared credentials
-- are refused for it).
ALTER TABLE device_credentials ADD COLUMN confirmed_at timestamptz;
ALTER TABLE device_credentials DROP CONSTRAINT device_credentials_kind_check;
ALTER TABLE device_credentials ADD CONSTRAINT device_credentials_kind_check
    CHECK (kind IN ('acs_auth', 'acs_auth_pending', 'connection_request',
                    'connection_request_pending', 'mqtt'));
