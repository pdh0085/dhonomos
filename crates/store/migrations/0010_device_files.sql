-- Files a device uploaded (vendor configuration backups, CO-08).
ALTER TABLE files ADD COLUMN device_id uuid REFERENCES devices (id) ON DELETE SET NULL;
CREATE INDEX files_device ON files (device_id, created_at DESC) WHERE device_id IS NOT NULL;
