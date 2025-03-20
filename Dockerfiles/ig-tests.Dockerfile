ARG BUILDER_IMAGE=golang:1.23.4-bullseye@sha256:6d4cbf0b3900afa3e4460ca995b6c351370ce8d2d44b7a964dc521ab640e1a88
ARG BASE_IMAGE=gcr.io/distroless/static-debian11:latest@sha256:1dbe426d60caed5d19597532a2d74c8056cd7b1674042b88f7328690b5ead8ed

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} AS builder

ARG TARGETARCH
ARG BUILDARCH

ARG GOPROXY
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum /cache/
RUN cd /cache && \
	go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget
WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/k8s
RUN \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go test \
      -c -o ig-integration-${TARGETARCH}.test ./...

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget integration tests for ig"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image is used to run integration tests for the ig binary."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

ARG TARGETARCH

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/k8s/ig-integration-${TARGETARCH}.test /usr/bin/ig-integration.test
ENTRYPOINT ["/usr/bin/ig-integration.test"]
