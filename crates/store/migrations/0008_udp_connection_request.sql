-- Where NATed CPEs receive UDP Connection Requests (CW-08): learned from the built-in
-- STUN server or the CPE's UDPConnectionRequestAddress parameter.
ALTER TABLE devices
    ADD COLUMN udp_cr_address text,
    ADD COLUMN udp_cr_seen_at timestamptz;
