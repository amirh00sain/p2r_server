# Spider Secure Tunnel (SPIDER-SEC-1)

The server requires the SPIDER-SEC-1 application-layer handshake immediately after the authenticated WebSocket upgrade. Every tunnel frame is authenticated and encrypted with AES-256-GCM using fresh per-connection keys derived from X25519 and the current tunnel token.

The Go server is deployed behind Railway's public HTTPS edge, which provides TLS 1.2/1.3 and WebSocket support. The application-layer encryption prevents the tunnel payload from being exposed to an intermediary that terminates the outer TLS connection.

The protocol is intentionally strict: unauthenticated, plaintext tunnel frames are rejected; replayed or out-of-order secure records are rejected.

## ClientHello note

SPIDER-SEC-1 cannot hide the outer TLS ClientHello. That requires TLS ECH at the public TLS terminator. Railway documents TLS 1.2/1.3 and WebSocket support, but ECH configuration is not part of this application protocol.
