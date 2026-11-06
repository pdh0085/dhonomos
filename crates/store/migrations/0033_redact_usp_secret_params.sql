-- A value marked as a secret in a SetParameterValues task (a password, a key) never enters the
-- parameter snapshot: over CWMP it is stored empty once the CPE took it. Over USP, earlier
-- versions stored it as set, in plain text, from the values requested or from those the Agent
-- echoed in its SetResp. This scrubs what they stored: every parameter some task of the
-- device set from a secret value is blanked. CWMP rows are empty already, so the statements
-- only touch rows that still hold a value, and running them again changes nothing.

-- The snapshot never keeps a secret (a parameter not read yet, NULL, stays as it is).
WITH secret AS (
    SELECT DISTINCT t.device_id, s.v ->> 'name' AS path
    FROM tasks t
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(t.payload -> 'values') = 'array'
             THEN t.payload -> 'values' ELSE '[]'::jsonb END) AS s (v)
    WHERE t.kind = 'set_parameter_values'
      AND s.v ->> 'secret' = 'true')
UPDATE device_params dp
SET value = ''
FROM secret
WHERE dp.device_id = secret.device_id
  AND dp.path = secret.path
  AND dp.value <> '';

-- A change event an Agent's ValueChange notification recorded for such a parameter kept the
-- snapshot's value, the secret, as `old` (and the Agent's as `new`).
WITH secret AS (
    SELECT DISTINCT t.device_id, s.v ->> 'name' AS path
    FROM tasks t
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(t.payload -> 'values') = 'array'
             THEN t.payload -> 'values' ELSE '[]'::jsonb END) AS s (v)
    WHERE t.kind = 'set_parameter_values'
      AND s.v ->> 'secret' = 'true')
UPDATE events ev
SET detail = jsonb_set(ev.detail, '{changes}', (
        SELECT jsonb_agg(
                   CASE WHEN EXISTS (
                            SELECT 1 FROM secret
                            WHERE secret.device_id = ev.device_id
                              AND secret.path = c.v ->> 'path')
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
        SELECT 1
        FROM jsonb_array_elements(ev.detail -> 'changes') AS p (v)
        JOIN secret ON secret.device_id = ev.device_id AND secret.path = p.v ->> 'path'
        WHERE coalesce(p.v ->> 'old', '') NOT IN ('', '********')
           OR coalesce(p.v ->> 'new', '') NOT IN ('', '********'))
      ELSE false END;
