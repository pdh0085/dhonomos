-- Agents that run a WebSocket server (US-05): the Controller connects to this URL.
ALTER TABLE devices ADD COLUMN usp_ws_url text;
