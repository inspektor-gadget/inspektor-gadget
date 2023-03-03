FROM ghcr.io/inspektor-gadget/ig-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s

RUN go test -c -o ig-integration.test ./...
