-- What happened to each task, step by step (queued, dispatched, waiting, retry, succeeded,
-- failed, cancelled, expired), for the task trace view. Appended by the same statements
-- that change the state, so it cannot drift from it.
ALTER TABLE tasks ADD COLUMN trace jsonb NOT NULL DEFAULT '[]'::jsonb;

-- One trace step: time, step name, attempt number and an optional detail.
CREATE FUNCTION task_step(step text, attempt integer, detail text DEFAULT NULL)
RETURNS jsonb LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT jsonb_build_array(jsonb_strip_nulls(jsonb_build_object(
        'at', now(), 'step', step, 'attempt', attempt, 'detail', detail)))
$$;
