ARG BUILDER_IMAGE=golang:1.21-bullseye
ARG BASE_IMAGE=gcr.io/distroless/static-debian11

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETARCH
ARG BUILDARCH

COPY go.mod go.sum /cache/
RUN cd /cache && \
	go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget
WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go test -c -o ig-integration-${TARGETARCH}.test ./...

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget integration tests for ig"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image is used to run integration tests for the ig binary."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

ARG TARGETARCH

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s/ig-integration-${TARGETARCH}.test /usr/bin/ig-integration.test
ENTRYPOINT ["/usr/bin/ig-integration.test"]
