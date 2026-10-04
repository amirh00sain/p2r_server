# Spider Server 2.0 secure setup

## Railway

Deploy the contents of this directory as the Railway service root. The included Dockerfile expects `go.mod`, `go.sum`, and the Go source files in the same build context.

Set at minimum:

```text
PORT=8080
PANEL_PASSWORD=<strong-random-password>
TRUST_PROXY=true
HEARTBEAT_INTERVAL=20s
```

Attach a Railway Volume mounted at `/data`. The server stores the SPIDER-SEC-1 static X25519 private key in:

`/data/server_static_x25519.key`

Without persistent `/data`, every fresh deployment generates a new server identity and clients with the previous pinned public key will intentionally refuse the connection.

## Startup output

The server prints:

`primary token: <current-token>`

and

`SPIDER-SEC-1 server public key: <base64url-public-key>`

Put both values into the client `client.json`.

## Security model

The public WebSocket upgrade no longer carries the tunnel token. Immediately after upgrade, SPIDER-SEC-1 performs a mutually authenticated application handshake. Tunnel frames are rejected unless the secure record authentication succeeds.
