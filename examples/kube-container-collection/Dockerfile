FROM golang:1.24.2-bullseye@sha256:f0fe88a509ede4f792cbd42056e939c210a1b2be282cfe89c57a654ef8707cd2 AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget/examples/kube-container-collection && make kube-container-collection-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/kube-container-collection/kube-container-collection-static /bin/kube-container-collection
CMD ["/bin/kube-container-collection"]
