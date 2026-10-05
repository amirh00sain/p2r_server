# Spider WSS Tunnel — server image
#
# Build with server/ as the context. go.mod lives in server/, so a context at
# the repository root would make every COPY below miss:
#
#   docker build -t spider-server ./server
#
# On Railway, set the service's root directory to `server/` and this file is
# found automatically with the right context.
#
# Run:
#
#   docker run -p 8080:8080 -e PANEL_PASSWORD=... -v spider-data:/data spider-server
#
# The Go toolchain version MUST stay >= the `go` directive in go.mod. Building
# with an older toolchain fails outright rather than degrading, and that
# failure shows up as a Railway deploy error rather than a runtime one.

FROM golang:1.24-alpine AS build
WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN go mod download

# _test.go files are copied too: `go build` ignores them for the binary, and
# keeping the directory layout intact avoids surprises with //go:embed.
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/spider-server .

# --- runtime -------------------------------------------------------------
# Distroless would be smaller still, but it has no shell for a HEALTHCHECK
# and no CA bundle for outbound TLS. Alpine + ca-certificates keeps the image
# small while staying debuggable when a deploy goes wrong.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 spider \
 && mkdir -p /data \
 && chown -R spider:spider /data

COPY --from=build /out/spider-server /usr/local/bin/spider-server
USER spider

# Railway injects PORT itself; these are the local defaults.
ENV PORT=8080 \
    DATA_DIR=/data

# EXPOSE documents the local default. Railway ignores it and routes to $PORT.
EXPOSE 8080

# The health endpoint is served by the same process the tunnel runs on, so a
# failing healthcheck means the process is not accepting traffic.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null "http://127.0.0.1:${PORT}/healthz" || exit 1

# Exec form (no shell): the Go process becomes PID 1 and receives SIGTERM
# directly, which is what makes the graceful drain in main() actually run.
ENTRYPOINT ["/usr/local/bin/spider-server"]
