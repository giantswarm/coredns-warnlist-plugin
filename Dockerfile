FROM golang:1.24.0 AS builder
WORKDIR /workspace

# Copy modules manifests
COPY go.mod go.mod
COPY go.sum go.sum

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY *.go ./
COPY cmd/ cmd/
COPY pkg/ pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o coredns ./cmd/coredns

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=builder /workspace/coredns .
USER nonroot:nonroot
EXPOSE 53 53/udp
ENTRYPOINT ["/coredns"]
