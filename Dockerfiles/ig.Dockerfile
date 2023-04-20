ARG BUILDER_IMAGE=golang:1.19
ARG BASE_IMAGE=gcr.io/distroless/static-debian11

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=undefined
ENV VERSION=${VERSION}

RUN \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y build-essential libseccomp2:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		apt-get install -y gcc-aarch64-linux-gnu crossbuild-essential-arm64 ; \
	fi

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

RUN \
	export CGO_ENABLED=1 ; \
	if [ "${TARGETARCH}" = 'arm64' ] ; then \
		export CC=aarch64-linux-gnu-gcc ; \
		export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig ; \
	fi ; \
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
		-ldflags "-X main.version=${VERSION} -extldflags '-static'" \
		-o ig-${TARGETOS}-${TARGETARCH} \
		github.com/inspektor-gadget/inspektor-gadget/cmd/ig

FROM ${BASE_IMAGE}

ARG TARGETOS
ARG TARGETARCH

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/ig-${TARGETOS}-${TARGETARCH} /usr/bin/ig
ENTRYPOINT ["/usr/bin/ig"]
