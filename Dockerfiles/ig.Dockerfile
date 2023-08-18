ARG BUILDER_IMAGE=golang:1.19
ARG BASE_IMAGE=gcr.io/distroless/static-debian11

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETOS
ARG TARGETARCH
ARG BUILDARCH
ARG VERSION=undefined
ENV VERSION=${VERSION}

RUN \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y build-essential libseccomp2:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
		if [ ${TARGETARCH} = 'arm64' ]; then \
			apt-get install -y gcc-aarch64-linux-gnu crossbuild-essential-arm64; \
		elif [ ${TARGETARCH} = 'amd64' ]; then \
			apt-get install -y gcc-x86-64-linux-gnu crossbuild-essential-amd64; \
		else \
			>&2 echo "${TARGETARCH} is not supported"; \
			exit 1; \
		fi \
	fi

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

RUN \
	export CGO_ENABLED=1 ; \
	if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
		if [ ${TARGETARCH} = 'arm64' ]; then \
			export CC=aarch64-linux-gnu-gcc; \
			export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig/; \
		elif [ ${TARGETARCH} = 'amd64' ]; then \
			export CC=x86_64-linux-gnu-gcc; \
			export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig; \
		else \
			>&2 echo "${TARGETARCH} is not supported"; \
			exit 1; \
		fi \
	fi; \
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
		-ldflags "-X main.version=${VERSION} -extldflags '-static'" \
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
