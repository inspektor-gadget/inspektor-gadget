FROM golang:1.22@sha256:192683db8982323952988c7b86c098ee7ecc6cbeb202bf7c113ff9be5358367c AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget/examples/runc-hook && make runc-hook-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/runc-hook/runc-hook-static /bin/runc-hook
ENTRYPOINT ["/bin/runc-hook"]
