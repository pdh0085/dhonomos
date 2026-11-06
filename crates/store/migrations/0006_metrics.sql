-- Device time series (DG-04/05): numeric samples in daily partitions on plain PostgreSQL
-- (no extension needed; retention drops whole partitions). See ADR-037.
CREATE TABLE metric_names (
    id    integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    path  text NOT NULL UNIQUE
);

CREATE TABLE metric_samples (
    device_id  uuid NOT NULL,
    metric_id  integer NOT NULL,
    ts         timestamptz NOT NULL,
    value      double precision NOT NULL
) PARTITION BY RANGE (ts);

CREATE INDEX metric_samples_series ON metric_samples (device_id, metric_id, ts);

-- Which metrics a device has, without scanning samples.
CREATE TABLE device_metrics (
    device_id  uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    metric_id  integer NOT NULL REFERENCES metric_names (id),
    last_ts    timestamptz NOT NULL,
    last_value double precision NOT NULL,
    PRIMARY KEY (device_id, metric_id)
);
