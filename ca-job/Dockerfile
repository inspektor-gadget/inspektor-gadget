FROM golang:1.25-trixie AS builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

COPY ./ /gadget
RUN cd /gadget && CGO_ENABLED=0 go build -o /get-cert -ldflags '-w -s' ./ca-job/

FROM busybox:stable
COPY --from=builder /get-cert /bin/get-cert
CMD ["/bin/get-cert"]
