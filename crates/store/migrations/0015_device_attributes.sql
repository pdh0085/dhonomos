-- Subscriber links and custom attributes (CO-13): external IDs such as a subscriber
-- number, PPPoE account or line ID, as string key/value pairs.
ALTER TABLE devices ADD COLUMN attributes jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(attributes) = 'object');

-- Exact lookups by attribute (`attributes @> '{"subscriber": "123"}'`).
CREATE INDEX devices_attributes ON devices USING gin (attributes jsonb_path_ops);
