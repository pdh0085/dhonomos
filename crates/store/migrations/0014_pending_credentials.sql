-- A Connection Request credential being provisioned: becomes `connection_request` once the
-- CPE accepted it (SetParameterValues succeeded).
ALTER TABLE device_credentials DROP CONSTRAINT device_credentials_kind_check;
ALTER TABLE device_credentials ADD CONSTRAINT device_credentials_kind_check
    CHECK (kind IN ('acs_auth', 'connection_request', 'connection_request_pending', 'mqtt'));
