-- Broker accounts issued to USP Agents (US-17).
ALTER TABLE device_credentials DROP CONSTRAINT device_credentials_kind_check;
ALTER TABLE device_credentials ADD CONSTRAINT device_credentials_kind_check
    CHECK (kind IN ('acs_auth', 'connection_request', 'mqtt'));
