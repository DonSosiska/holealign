# syntax=docker/dockerfile:1
# Build context: repository root (see docker-compose.yml).
FROM golang:1.27.4@sha256:fe517acaa580cc7915457080f850c37e618b3c1e750f98b58fc6429b605147a1 AS build
ENV CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY rules ./rules
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-X main.version=e2e" -o /out/ ./cmd/holealign-server ./cmd/holealign-agent

# ---- holealign-server --------------------------------------------------------
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS server
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/holealign-server /usr/local/bin/holealign-server
COPY rules /usr/share/holealign/rules
ENV HOLEALIGN_DATA_DIR=/var/lib/holealign
VOLUME /var/lib/holealign
ENTRYPOINT ["/usr/local/bin/holealign-server"]
CMD ["serve"]

# ---- host: current Debian 12 base, packages from the 2024-06-01 snapshot -------------
# openssh-server is pinned to 1:9.2p1-2+deb12u2 (vulnerable to CVE-2024-6387) on purpose: the
# e2e run expects an EXPLOITABLE alert for it and then a RESOLVED one after upgrading it.
FROM debian:bookworm-20261104-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS host
RUN rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list \
    && printf '%s\n' \
      'deb http://snapshot.debian.org/archive/debian/20240601T000000Z bookworm main' \
      'deb http://snapshot.debian.org/archive/debian-security/20240601T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\nAcquire::http::Timeout "30";\n' \
      > /etc/apt/apt.conf.d/99snapshot
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       openssh-server=1:9.2p1-2+deb12u2 nginx ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd
COPY --from=build /out/holealign-agent /usr/local/bin/holealign-agent
COPY deploy/e2e/host-entrypoint.sh /usr/local/bin/host-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/host-entrypoint.sh"]
