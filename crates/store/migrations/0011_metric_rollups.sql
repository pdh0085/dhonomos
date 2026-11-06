-- Compacted time series (ADR-044): one row per device, metric and UTC day with the
-- sample offsets (seconds into the day) and values as arrays. Rows over ~2 kB are
-- compressed by TOAST, so a 5-minute series costs a few bytes per sample.
CREATE TABLE metric_rollups (
    device_id  uuid NOT NULL,
    metric_id  integer NOT NULL,
    day        date NOT NULL,
    offsets    integer[] NOT NULL,
    vals       double precision[] NOT NULL,
    PRIMARY KEY (device_id, metric_id, day)
);

CREATE INDEX metric_rollups_day ON metric_rollups (day);
