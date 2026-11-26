# syntax=docker/dockerfile:1.7
#
# Leazone image: web UI build, static Go build, then a minimal "scratch" image
# running as UID 1000 with file capabilities in the permitted set only.
#
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 .
# (the last stage runs the target binary once, so cross builds need QEMU/binfmt).

ARG NODE_IMAGE=node:22-alpine
ARG GO_IMAGE=golang:1.26-alpine

# ---- 1. Web UI -------------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY api/openapi.yaml /src/api/openapi.yaml
COPY web/ ./
RUN npm run build

# ---- 2. Go binary ----------------------------------------------------------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
      -ldflags "-s -w -X github.com/prohand/leazone/internal/version.Version=${VERSION} \
        -X github.com/prohand/leazone/internal/version.Commit=${COMMIT} \
        -X github.com/prohand/leazone/internal/version.BuildDate=${BUILD_DATE}" \
      -o /out/leazone ./cmd/leazone
# Minimal root filesystem: user leazone (1000:1000) and writable mount points.
RUN mkdir -p /out/rootfs/etc /out/rootfs/config /out/rootfs/data /out/rootfs/logs /out/rootfs/tmp \
 && echo 'leazone:x:1000:1000:Leazone:/data:/sbin/nologin' > /out/rootfs/etc/passwd \
 && echo 'leazone:x:1000:' > /out/rootfs/etc/group \
 && chown 1000:1000 /out/rootfs/config /out/rootfs/data /out/rootfs/logs \
 && chmod 1777 /out/rootfs/tmp

# ---- 3. Final image ----------------------------------------------------------
FROM scratch
ARG VERSION=0.0.0-dev
LABEL org.opencontainers.image.title="Leazone" \
      org.opencontainers.image.description="Lightweight DNS + DHCP server with high availability" \
      org.opencontainers.image.source="https://github.com/prohand/leazone" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="NOASSERTION"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/rootfs/ /
COPY --from=build /out/leazone /leazone
# File capabilities must be written in this stage: they are lost by COPY --from.
# "+p" only, so the container still starts when NET_ADMIN is not granted.
RUN ["/leazone", "internal", "setcap", "/leazone"]
USER 1000:1000
WORKDIR /data
EXPOSE 53/udp 53/tcp 67/udp 8443/tcp 7443/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["/leazone", "healthcheck"]
ENTRYPOINT ["/leazone"]
CMD ["serve"]
