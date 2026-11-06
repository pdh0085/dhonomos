-- Two-factor authentication with a time-based one-time password (ADR-100, RFC 6238).
--
-- One row per account that has started or finished enrolling. The secret is encrypted with
-- the secrets key (AAD `totp:<user id>`, re-sealed on key rotation). A new secret waits in the
-- `pending_*` columns until a code from it is shown (setup), and then replaces the active one;
-- the active secret keeps working until then, so a lost phone can be replaced without a gap.
-- `last_step` is the newest 30-second step a code was accepted for: a code is refused unless
-- its step is newer (no replay).
CREATE TABLE user_totp (
    user_id             uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    ciphertext          bytea,
    nonce               bytea,
    key_id              text,
    enabled_at          timestamptz,
    last_step           bigint,
    pending_ciphertext  bytea,
    pending_nonce       bytea,
    pending_key_id      text,
    pending_at          timestamptz,
    CHECK ((ciphertext IS NULL) = (nonce IS NULL) AND (nonce IS NULL) = (key_id IS NULL)
           AND (key_id IS NULL) = (enabled_at IS NULL)),
    CHECK ((pending_ciphertext IS NULL) = (pending_nonce IS NULL)
           AND (pending_nonce IS NULL) = (pending_key_id IS NULL)
           AND (pending_key_id IS NULL) = (pending_at IS NULL)),
    CHECK (enabled_at IS NOT NULL OR pending_at IS NOT NULL)
);

-- Single-use recovery codes, stored as SHA-256 hashes (the codes carry 80 bits of entropy);
-- using one deletes it.
CREATE TABLE user_recovery_codes (
    user_id     uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash   bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash)
);

-- A session made by single sign-on: the identity provider handled the second factor, so
-- the admin requirement does not apply to it. Sessions from before this are password
-- sessions.
ALTER TABLE sessions ADD COLUMN sso boolean NOT NULL DEFAULT false;
