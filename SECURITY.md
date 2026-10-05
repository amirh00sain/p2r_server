# Spider Secure Tunnel — SPIDER-SEC-3

The server requires the SPIDER-SEC-3 application-layer handshake immediately
after the WebSocket upgrade. Tunnel frames are rejected unless the secure
record authentication succeeds. The local SOCKS5 and web panel are unchanged.

## Credential identification without a plaintext lookup

SPIDER-SEC-1 sent `SHA256(prefix || token)` in the clear as a server-side
selector. That value was a stable, linkable fingerprint of the credential: an
observer could match every connection made with it, confirm at a glance that
this was a Spider client, and — against a low-entropy token — recover the
token offline.

SEC-3 removed it. The server cannot know which credential to use before it
decrypts, so it tries each one: it derives a candidate key for every stored
credential and attempts the AEAD open. Exactly one succeeds. The loop always
runs to completion so the time taken does not reveal how many credentials
exist, and a per-IP rate limit bounds its cost.

Two consequences, both handled:

- **Credential strength is part of the security argument.** An observer can
  compute the X25519 shared secret from the pinned public key, so offline
  guessing against a captured inner hello is bounded only by token entropy.
  The server's token generator retries until it produces one that the client
  will accept — any credential weaker than 128 estimated bits is refused
  before a single byte is sent.
- **Trial decryption is measurable work**, so it is rate limited per source IP.

## Authentication

Both sides prove possession of the token before any data key is installed:

- The client encrypts `ClientHelloInner` under a key derived from the shared
  secret and the token — the server can only open it if it knows the token.
- The server signs the transcript with a key derived from the shared secret
  and the token — the client can only verify it if the token matches.
- The client proves back the transcript bound to the server's ephemeral hello.

An authenticator that holds neither the token nor the pinned X25519 private
key cannot complete the exchange. A relay that terminates TLS and forwards
bytes cannot fabricate either proof.

## Protocol strictness

- Unauthenticated or plaintext tunnel frames are rejected.
- Replay, reordering and epoch regression in the record layer are rejected.
- The AEAD offered inside the encrypted inner hello must be echoed back; a
  server that selects a different one is rejected before any data flows.
- A missing or unknown top-level field in the outer cover profile is a fatal
  error, not a silent fallback. Falling back to a plain Go hello is worse than
  refusing to start.

## Suite

X25519 + HKDF-SHA256 + AES-256-GCM (default, negotiable to ChaCha20-Poly1305).
Everything uses standard library or widely-reviewed constructions; no custom
cryptographic algorithm is used.

The public WebSocket upgrade carries no tunnel credential, no version
signalling and no subprotocol name. The subprotocol is `chat`.

The protocol is deployed behind Railway's public HTTPS edge, which provides
TLS 1.2/1.3 and WebSocket support. The application-layer encryption prevents
the tunnel payload from being exposed to an intermediary that terminates the
outer TLS connection.

## What this does not hide

The outer TLS ClientHello is not encrypted by this protocol, and the SNI in it
is readable by anyone on the path unless the endpoint terminates Encrypted
ClientHello. Setting `"fingerprint": "chrome"` makes the ClientHello look like
a browser's — it does not make the connection to `snapp.ir` less visible.

The tunnel payload is protected even against such an intermediary. What
survives is the outer session itself — which host you dialled, when, and how
much you sent — not which credential you used.

## Logs

A successful handshake logs:

```
[SEC3] outer hello received (sni=... fingerprint=...)
[SEC3] inner hello decrypted (client=... features=... aead=...)
[SEC3] client authenticated (user=...)
[SEC3] tunnel ready (user=... aead=...)
```

The fourth line means the record layer is installed and tunnel traffic is in
flight.

## See also

`SECURE_SETUP.md` in the server directory for the operator setup.
`client/SECURITY.md` for the client's side of the same handshake.