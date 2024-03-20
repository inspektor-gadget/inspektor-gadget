FROM --platform=$BUILDPLATFORM golang:1.21-bullseye as builder
ENV GO111MODULE=on
ENV CGO_ENABLED=0
WORKDIR /src
ARG TARGETOS TARGETARCH
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -o /out/container-network-tracer examples/gadgets/withfilter/trace/network/network.go

FROM gcr.io/distroless/static-debian11:latest
COPY --from=builder /out/container-network-tracer /usr/bin/container-network-tracer
WORKDIR /root
ENTRYPOINT ["container-network-tracer"]
