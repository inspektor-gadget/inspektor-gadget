FROM golang:1.20 as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget/examples/runc-hook && make runc-hook-static

FROM busybox
COPY --from=builder /gadget/examples/runc-hook/runc-hook-static /bin/runc-hook
ENTRYPOINT /bin/runc-hook
