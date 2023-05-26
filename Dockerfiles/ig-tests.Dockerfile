ARG BUILDER_IMAGE=golang:1.19
ARG BASE_IMAGE=gcr.io/distroless/static-debian11

FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETARCH

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y gcc build-essential libseccomp-dev:${TARGETARCH} && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		apt-get install -y gcc-aarch64-linux-gnu crossbuild-essential-arm64 ; \
	fi

COPY go.mod go.sum /cache/
RUN cd /cache && \
	go mod download
ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget
WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s
RUN GOARCH=${TARGETARCH} go test -c -o ig-integration-${TARGETARCH}.test ./...

FROM ${BASE_IMAGE}

ARG TARGETARCH

COPY --from=builder /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/ig/k8s/ig-integration-${TARGETARCH}.test /usr/bin/ig-integration.test
ENTRYPOINT ["/usr/bin/ig-integration.test"]
