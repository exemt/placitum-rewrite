FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/rewrite ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/rewrite-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/rewrite" \
      org.opencontainers.image.description="Placitum rewrite inspector: response modification groups" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-rewrite" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/rewrite /out/rewrite-probe /usr/local/bin/
COPY profiles ./profiles
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 rewrite && \
    mkdir -p /var/lib/waf/rewrite && \
    chown -R rewrite:rewrite /var/lib/waf
USER rewrite

ENV NATS_URL=nats://nats:4222 \
    WAF_REWRITE_SUBJECT=waf.req.rewrite \
    WAF_REWRITE_NAME=rewrite \
    WAF_REWRITE_PROFILES=/app/profiles \
    WAF_REWRITE_DATA=/var/lib/waf/rewrite \
    WAF_REWRITE_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD ["rewrite-probe", "--quiet", "--timeout", "1s", "--uri", "/healthcheck"]

CMD ["rewrite"]
