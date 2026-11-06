-- The STUN password the ACS writes to a CPE (the SetParameterValues of `system:stun`) was queued
-- as plaintext and, once the CPE took it, stored in the parameter snapshot. From now on it is a
-- secret value of the task like every password: encrypted in the queue when the server has a
-- key, shown as `********` by the API, and empty in the snapshot. This scrubs what earlier
-- versions stored. The statements only touch rows that still hold the value, so running them
-- again changes nothing.

-- The snapshot never keeps a secret (CPEs report them empty).
UPDATE device_params
SET value = ''
WHERE path LIKE '%.ManagementServer.STUNPassword'
  AND value IS NOT NULL AND value <> '';

-- Finished STUN setups cannot run again: the password is replaced, and marked as a secret so
-- that the API shows it like the others.
UPDATE tasks t
SET payload = jsonb_set(t.payload, '{values}', (
        SELECT jsonb_agg(
                   CASE WHEN e.v ->> 'name' LIKE '%.ManagementServer.STUNPassword'
                        THEN e.v || '{"value": "********", "secret": true}'::jsonb
                        ELSE e.v
                   END
                   ORDER BY e.ord)
        FROM jsonb_array_elements(t.payload -> 'values') WITH ORDINALITY AS e (v, ord)))
WHERE t.created_by = 'system:stun'
  AND t.kind = 'set_parameter_values'
  AND t.state NOT IN ('pending', 'running')
  AND CASE WHEN jsonb_typeof(t.payload -> 'values') = 'array' THEN EXISTS (
        SELECT 1 FROM jsonb_array_elements(t.payload -> 'values') AS p (v)
        WHERE p.v ->> 'name' LIKE '%.ManagementServer.STUNPassword'
          AND coalesce(p.v ->> 'secret', 'false') <> 'true')
      ELSE false END;

-- Queued or running ones still have to be sent, so they keep the value; it is only marked as a
-- secret (the dispatcher takes a plain secret as it is), and the API shows it as `********`.
UPDATE tasks t
SET payload = jsonb_set(t.payload, '{values}', (
        SELECT jsonb_agg(
                   CASE WHEN e.v ->> 'name' LIKE '%.ManagementServer.STUNPassword'
                        THEN e.v || '{"secret": true}'::jsonb
                        ELSE e.v
                   END
                   ORDER BY e.ord)
        FROM jsonb_array_elements(t.payload -> 'values') WITH ORDINALITY AS e (v, ord)))
WHERE t.created_by = 'system:stun'
  AND t.kind = 'set_parameter_values'
  AND t.state IN ('pending', 'running')
  AND CASE WHEN jsonb_typeof(t.payload -> 'values') = 'array' THEN EXISTS (
        SELECT 1 FROM jsonb_array_elements(t.payload -> 'values') AS p (v)
        WHERE p.v ->> 'name' LIKE '%.ManagementServer.STUNPassword'
          AND coalesce(p.v ->> 'secret', 'false') <> 'true')
      ELSE false END;

-- A change event of an Inform that reported the password keeps the snapshot's value as `old`
-- (and the CPE's as `new`).
UPDATE events ev
SET detail = jsonb_set(ev.detail, '{changes}', (
        SELECT jsonb_agg(
                   CASE WHEN c.v ->> 'path' LIKE '%.ManagementServer.STUNPassword'
                        THEN c.v || jsonb_build_object(
                                 'old', CASE WHEN coalesce(c.v ->> 'old', '') = ''
                                             THEN c.v -> 'old' ELSE '"********"'::jsonb END,
                                 'new', CASE WHEN coalesce(c.v ->> 'new', '') = ''
                                             THEN c.v -> 'new' ELSE '"********"'::jsonb END)
                        ELSE c.v
                   END
                   ORDER BY c.ord)
        FROM jsonb_array_elements(ev.detail -> 'changes') WITH ORDINALITY AS c (v, ord)))
WHERE ev.kind = 'parameter_change'
  AND CASE WHEN jsonb_typeof(ev.detail -> 'changes') = 'array' THEN EXISTS (
        SELECT 1 FROM jsonb_array_elements(ev.detail -> 'changes') AS p (v)
        WHERE p.v ->> 'path' LIKE '%.ManagementServer.STUNPassword'
          AND (coalesce(p.v ->> 'old', '') NOT IN ('', '********')
               OR coalesce(p.v ->> 'new', '') NOT IN ('', '********')))
      ELSE false END;
