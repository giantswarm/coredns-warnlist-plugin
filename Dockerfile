# Builds CoreDNS with this plugin compiled in (./cmd/coredns).
#
# The build stage is pinned to the build host platform and cross-compiles via
# GOOS/GOARCH, so the multi-arch buildx build never runs Go under QEMU
# (architect-orb docs/multi-arch-dockerfiles.md, pattern B). The generated
# architect/go-build job cannot produce this binary: it builds the repo root,
# which is the plugin library package, not a main package.
FROM --platform=$BUILDPLATFORM gsoci.azurecr.io/giantswarm/golang:1.27.0-alpine3.23 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w" -o /out/coredns ./cmd/coredns

# Grant the binary cap_net_bind_service as a *file* capability, exactly as the
# upstream coredns Dockerfile does. Kubernetes leaves the kernel's unprivileged
# port floor at 1024 and does not give a non-root process ambient capabilities,
# so without this the nonroot image cannot bind :53 even when the pod adds
# NET_BIND_SERVICE. setcap only writes an xattr, so it works on the
# cross-compiled target binary from the host-platform stage.
FROM --platform=$BUILDPLATFORM gsoci.azurecr.io/giantswarm/golang:1.27.0-alpine3.23 AS caps
# libcap is unpinned on purpose: Alpine drops superseded package versions from
# its mirrors, so a pinned version would break the build at the next Alpine
# point release. The Alpine release itself is pinned by the base image tag.
# hadolint ignore=DL3018
RUN apk add --no-cache libcap
COPY --from=build /out/coredns /coredns
RUN setcap cap_net_bind_service=+ep /coredns

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=caps /coredns /coredns
# Numeric uid/gid (distroless "nonroot" is 65532) so Kubernetes can verify the
# image runs as non-root when runAsNonRoot is set; a named user cannot be
# checked without /etc/passwd resolution. Mirrors upstream coredns.
USER 65532:65532
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
