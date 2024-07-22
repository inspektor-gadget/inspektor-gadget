FROM --platform=$BUILDPLATFORM golang:1.22-bullseye@sha256:11ff2c5de8044d8d749cc684f6f3cdfbc9b2755960a62d4948b3483dc090e7aa AS builder
ENV GO111MODULE=on
ENV CGO_ENABLED=0
WORKDIR /src
ARG TARGETOS TARGETARCH
RUN --mount=target=. \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -o /out/container-network-tracer examples/builtin-gadgets/withfilter/trace/network/network.go

FROM gcr.io/distroless/static-debian11:latest@sha256:1dbe426d60caed5d19597532a2d74c8056cd7b1674042b88f7328690b5ead8ed
COPY --from=builder /out/container-network-tracer /usr/bin/container-network-tracer
WORKDIR /root
ENTRYPOINT ["container-network-tracer"]
