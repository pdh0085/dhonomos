-- A btree index row is limited to about 2.7 KB, so `device_params_path_value (path, value)`
-- refused any parameter whose value is longer (a certificate PEM, `DeviceInfo.DeviceLog` with
-- up to 32 KiB of log text). The single INSERT ... ON CONFLICT of a whole read failed with
-- "index row size ... exceeds btree version 4 maximum 2704", so one such value lost every
-- parameter reported with it.
--
-- The new index keeps only the first 256 characters of the value (at most 1 KiB), which cannot
-- overflow. Equality searches (`param.<path> = value`) match it with `left(value, 256) =
-- left($1, 256)` and then compare the whole value (`crates/store/src/filter.rs`). Pattern
-- searches (ILIKE) and numeric comparisons cannot use a btree on the value in any case.
--
-- On a very large table the build blocks writes to `device_params` while it runs. To avoid
-- that, create the index by hand beforehand with CREATE INDEX CONCURRENTLY under the same
-- name; IF NOT EXISTS then skips the build here.
DROP INDEX device_params_path_value;
CREATE INDEX IF NOT EXISTS device_params_path_value_prefix
    ON device_params (path, left(value, 256));
