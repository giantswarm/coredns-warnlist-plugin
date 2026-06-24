# The coredns binary is built by architect/go-build and persisted as`coredns-linux-<arch>`.
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
ARG TARGETARCH
COPY coredns-linux-${TARGETARCH} /coredns
USER nonroot:nonroot
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
