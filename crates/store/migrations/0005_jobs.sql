-- Bulk jobs (CO-15) and firmware campaigns (FW-02/03). See docs/design/05-bulk-jobs.md.
CREATE TABLE jobs (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    name          text NOT NULL,
    target        jsonb NOT NULL,
    task_kind     text NOT NULL,
    task_payload  jsonb NOT NULL DEFAULT '{}',
    policy        jsonb NOT NULL DEFAULT '{}',
    state         text NOT NULL DEFAULT 'draft'
                  CHECK (state IN ('draft', 'running', 'paused', 'completed', 'cancelled')),
    stage         integer NOT NULL DEFAULT 0,
    reason        text,
    total         integer NOT NULL DEFAULT 0,
    created_by    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    started_at    timestamptz,
    finished_at   timestamptz,
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX jobs_tenant_created ON jobs (tenant_id, created_at DESC);
CREATE INDEX jobs_running ON jobs (id) WHERE state = 'running';

CREATE TABLE job_devices (
    job_id           uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    device_id        uuid NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    rank             integer NOT NULL,
    state            text NOT NULL DEFAULT 'queued'
                     CHECK (state IN ('queued', 'dispatched', 'verifying', 'succeeded', 'failed', 'cancelled')),
    task_id          uuid,
    dispatched_at    timestamptz,
    verify_deadline  timestamptz,
    finished_at      timestamptz,
    error            text,
    PRIMARY KEY (job_id, device_id)
);

CREATE INDEX job_devices_progress ON job_devices (job_id, state, rank);

ALTER TABLE tasks ADD COLUMN job_id uuid REFERENCES jobs (id) ON DELETE SET NULL;
CREATE INDEX tasks_job ON tasks (job_id, state) WHERE job_id IS NOT NULL;
