-- Files a device uploaded (vendor configuration and log files) go with the device instead of
-- staying behind with `device_id` NULL, outside every device scope (audit L-7). The API also
-- removes their content from storage when it deletes a device.
ALTER TABLE files
    DROP CONSTRAINT files_device_id_fkey,
    ADD CONSTRAINT files_device_id_fkey FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE;
