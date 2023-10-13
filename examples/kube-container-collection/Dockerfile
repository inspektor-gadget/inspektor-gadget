FROM golang:1.20 as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget/examples/kube-container-collection && make kube-container-collection-static

FROM busybox
COPY --from=builder /gadget/examples/kube-container-collection/kube-container-collection-static /bin/kube-container-collection
CMD /bin/kube-container-collection
