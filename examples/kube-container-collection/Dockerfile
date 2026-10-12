FROM golang:1.26.9-trixie@sha256:cf7e928cb9edc2ed8b3cc6fe77ee1ee30b9fea28149564c8840097321a7600ea AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
COPY examples/go.mod examples/go.sum /gadget/examples/
RUN cd /gadget/examples/kube-container-collection && make kube-container-collection-static

FROM busybox@sha256:9ae97d36d26566ff84e8893c64a6dc4fe8ca6d1144bf5b87b2b85a32def253c7
COPY --from=builder /gadget/examples/kube-container-collection/kube-container-collection-static /bin/kube-container-collection
CMD ["/bin/kube-container-collection"]
