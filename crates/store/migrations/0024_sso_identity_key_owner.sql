-- Single sign-on accounts are keyed by the provider's stable identity, not by the claims
-- that can change (audit L-11): the issuer and the user's subject (`iss` + `sub`). An
-- account made before this (`sso:<name>`) has none until its next login attaches them.
ALTER TABLE users
    ADD COLUMN oidc_issuer  text,
    ADD COLUMN oidc_subject text,
    ADD CONSTRAINT users_oidc_identity CHECK ((oidc_issuer IS NULL) = (oidc_subject IS NULL));

CREATE UNIQUE INDEX users_oidc_identity_key
    ON users (tenant_id, oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;

-- An API key made by an operator account works only while that account exists and is
-- enabled (audit L-13): deleting the account deletes its keys, disabling it stops them
-- (checked when the key is used). NULL: made with the static token or by another key.
ALTER TABLE api_keys ADD COLUMN created_by_user uuid REFERENCES users (id) ON DELETE CASCADE;

CREATE INDEX api_keys_created_by_user ON api_keys (created_by_user) WHERE created_by_user IS NOT NULL;

-- Keys made before this by an account are tied to the account of that name. The actors of
-- keys made with the static token or by another key (`api-token`, `anonymous`, `key:...`)
-- are not account names.
UPDATE api_keys k SET created_by_user = u.id
FROM users u
WHERE u.tenant_id = k.tenant_id AND u.username = k.created_by
  AND k.created_by NOT IN ('api-token', 'anonymous') AND k.created_by NOT LIKE 'key:%';
