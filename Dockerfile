# Spider WSS Tunnel — server image
#
# Build from the REPOSITORY ROOT (that is what Railway uses as context):
#
#   docker build -f server/Dockerfile -t spider-server .
#
# Run:
#
#   docker run -p 8080:8080 -e TOKEN=... -v spider-data:/data spider-server

FROM golang:1.22-alpine AS build
WORKDIR /src

# Cache module downloads separately from source changes.
COPY server/go.mod server/go.sum ./
RUN go mod download

COPY server/*.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/spider-server .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 spider \
 && mkdir -p /data \
 && chown -R spider:spider /data

COPY --from=build /out/spider-server /usr/local/bin/spider-server
USER spider
ENV PORT=8080 \
    DATA_DIR=/data

# Railway injects PORT itself; EXPOSE documents the local default.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O - "http://127.0.0.1:${PORT}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/spider-server"]
