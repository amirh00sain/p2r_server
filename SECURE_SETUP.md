# Spider Server — SPIDER-SEC-3 setup

## Railway

Deploy the contents of this directory as the Railway service root. The included
Dockerfile expects `go.mod`, `go.sum` and the Go source files in the same build
context.

Set at minimum:

```text
PORT=8080
PANEL_PASSWORD=<strong-random-password>
TRUST_PROXY=true
```

Attach a Railway Volume mounted at `/data` if you intend to issue secondary
credentials at runtime. The primary token is regenerated on every fresh start
regardless.

## Startup output

The server prints:

```text
primary token: <hex-token>
SPIDER-SEC-3 server public key: <base64url-public-key>
```

Copy both values into the client `client.json`. They change on every restart
by default — the primary token is generated fresh for that reason, so a
credential copied from a backup log is invalid after the next boot.

Secondary credentials issued at runtime appear in the web panel, or:

```fish
./spider-server -print-token
```

which prints the current primary token and exits.

## Web panel

`http://0.0.0.0:<port>/` — HTTP Basic, user `admin`, password
`$PANEL_PASSWORD`. The panel exposes the current primary token, the list of
secondary credentials and the relay session table. The public token is what
clients use; the panel is the operator interface.

## Environment

Everything below has a working default — a bare `./spider-server` boots fine.
The most useful variables:

```text
PANEL_PASSWORD=<strong>          # HTTP Basic password for the web panel
TRUST_PROXY=true                 # forward real client IP from X-Forwarded-For
HANDSHAKE_RATE_LIMIT=10          # per-IP limit for the trial-decryption loop (per minute)
AEAD=aes-256-gcm                 # record cipher; "chacha20-poly1305" is accepted
KEY_ROTATE_BYTES=1073741824      # epoch advance per byte sent (default 1 GiB)
KEY_ROTATE_SECONDS=1h            # epoch advance per interval
```

### Padding (off by default)

```text
PADDING_ENABLED=true
PADDING_SIZES=4096,16384,51200
PADDING_WEIGHTS=0.7,0.25,0.05
PADDING_MIN_INTERVAL=2s
PADDING_MAX_INTERVAL=45s
PADDING_MAX_KBPS=64
```

Padding is opt-in. A constant-size frame on a fixed timer is itself a
fingerprint, so shipping it enabled would make the tunnel *easier* to classify.
When enabled, sizes are drawn from a weighted set, the interval is uniform
over a window, and the rate is capped. Padding records are authenticated and
discarded by the peer before the frame decoder runs.

## Data directory

Secondary credentials issued via the panel are persisted at `$DATA_DIR/token.json`
(0600). The primary credential is never persisted: it is generated fresh on
every start and the previous one is retired. If you need a stable credential
for automation, issue one through the panel rather than relying on the primary.

## Security model

The public WebSocket upgrade carries no tunnel credential. Immediately after
upgrade, SPIDER-SEC-3 performs a mutually authenticated application handshake
in which the credential is never visible on the wire. Tunnel frames are
rejected unless the secure record authentication succeeds.

The identity of the caller is recovered by trial decryption, not by a
plaintext lookup. The credential stays inside the protocol, and the server
cannot identify a caller faster than the cost of the loop over the store.