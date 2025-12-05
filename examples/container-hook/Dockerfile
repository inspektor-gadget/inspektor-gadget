FROM golang:1.25.5-trixie@sha256:4f9d98ebaa759f776496d850e0439c48948d587b191fc3949b5f5e4667abef90 AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget/examples/container-hook && make container-hook-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/container-hook/container-hook-static /bin/container-hook
ENTRYPOINT ["/bin/container-hook"]
