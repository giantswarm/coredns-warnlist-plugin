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

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/coredns /coredns
USER nonroot:nonroot
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
