-- Look up per-device CPE credentials by username during authentication (CO-16).
CREATE INDEX device_credentials_username ON device_credentials (kind, username);
