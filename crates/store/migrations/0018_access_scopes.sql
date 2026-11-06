-- Device scopes for operators and API keys (NB-04, ADR-074): which devices a caller may
-- see and act on. NULL means every device of the tenant. Keys: tags (all of), attributes
-- (exact values), protocol, oui, product_class; all conditions must hold.
ALTER TABLE users ADD COLUMN scope jsonb CHECK (jsonb_typeof(scope) = 'object');
ALTER TABLE api_keys ADD COLUMN scope jsonb CHECK (jsonb_typeof(scope) = 'object');

-- Whether device `d` is inside `scope` (NULL: always). The same rule as
-- `DeviceScope::matches` in Rust; tests check both against the same cases. A single
-- expression without sub-selects, and STABLE like `to_jsonb`, so the planner inlines it
-- (an IMMUTABLE function calling a STABLE one would run once per row).
CREATE FUNCTION device_in_scope(d devices, scope jsonb) RETURNS boolean
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT scope IS NULL OR (
        to_jsonb(d.tags) @> COALESCE(scope -> 'tags', '[]'::jsonb)
        AND d.attributes @> COALESCE(scope -> 'attributes', '{}'::jsonb)
        AND (scope ->> 'protocol' IS NULL OR d.protocol = scope ->> 'protocol')
        AND (scope ->> 'oui' IS NULL OR d.oui = scope ->> 'oui')
        AND (scope ->> 'product_class' IS NULL OR d.product_class = scope ->> 'product_class')
    )
$$;
