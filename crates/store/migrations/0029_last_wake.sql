-- How a device was last woken (a Connection Request, or a wake of a USP Agent): when, by which
-- way (`xmpp`, `http`, `udp` or `usp`; NULL when nothing was sent) and the outcome as the API
-- words it ("sent over XMPP", "failed: ..."). Written by the Waker after every attempt, one
-- UPDATE each, so that operators can see how a device is reached (docs/guide/operations.md).
ALTER TABLE devices
    ADD COLUMN last_wake_at timestamptz,
    ADD COLUMN last_wake_method text,
    ADD COLUMN last_wake_outcome text;
