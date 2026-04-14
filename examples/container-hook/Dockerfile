FROM golang:1.25.9-trixie@sha256:091e6099f4a58e9393b8cc5615622a59c1cef64481b0ffcf349ec1574449059e AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget/examples/container-hook && make container-hook-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/container-hook/container-hook-static /bin/container-hook
ENTRYPOINT ["/bin/container-hook"]
