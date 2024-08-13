FROM golang:1.22@sha256:829eff99a4b2abffe68f6a3847337bf6455d69d17e49ec1a97dac78834754bd6 AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget/examples/kube-container-collection && make kube-container-collection-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/kube-container-collection/kube-container-collection-static /bin/kube-container-collection
CMD ["/bin/kube-container-collection"]
