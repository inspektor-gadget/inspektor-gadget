ARG BUILDER_IMAGE=golang:1.19
ARG BASE_IMAGE=gcr.io/distroless/static-debian11

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETOS
ARG TARGETARCH
ARG BUILDARCH
ARG VERSION=undefined
ENV VERSION=${VERSION}
ARG EBPF_BUILDER=ghcr.io/inspektor-gadget/ebpf-builder:latest
ENV EBPF_BUILDER=${EBPF_BUILDER}

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
		-ldflags "-X github.com/inspektor-gadget/inspektor-gadget/cmd/common.version=${VERSION} \
                  -X github.com/inspektor-gadget/inspektor-gadget/cmd/common/image.builderImage=${EBPF_BUILDER} \
                  -extldflags '-static'" \
		-tags "netgo" \
		-o ig-${TARGETOS}-${TARGETARCH} \
		github.com/inspektor-gadget/inspektor-gadget/cmd/ig

FROM ${BASE_IMAGE}

ARG TARGETOS
ARG TARGETARCH

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget ig tool"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image only includes the ig binary, a standalone tool to run the gadgets."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/ig-${TARGETOS}-${TARGETARCH} /usr/bin/ig
ENV HOST_ROOT=/host
ENTRYPOINT ["/usr/bin/ig"]
