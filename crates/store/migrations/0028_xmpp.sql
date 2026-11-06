-- The built-in XMPP server for Connection Requests (ADR-104, docs/design/12-xmpp-server.md):
-- a device's XMPP password (`xmpp`, and `xmpp_pending` while it is being provisioned; the
-- device's first login with the pending one makes it `xmpp`), and when the device's XMPP
-- session started. `xmpp_connected_at` is written when a session binds and cleared when it
-- ends (never per stanza), and cleared for everyone when the XMPP server starts, because
-- sessions do not survive a restart.
ALTER TABLE device_credentials DROP CONSTRAINT device_credentials_kind_check;
ALTER TABLE device_credentials ADD CONSTRAINT device_credentials_kind_check
    CHECK (kind IN ('acs_auth', 'acs_auth_pending', 'connection_request',
                    'connection_request_pending', 'mqtt', 'xmpp', 'xmpp_pending'));
ALTER TABLE devices ADD COLUMN xmpp_connected_at timestamptz;
