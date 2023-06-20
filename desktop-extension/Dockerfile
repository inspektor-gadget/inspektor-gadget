ARG BUILDER_IMAGE=golang:1.19

# Building Golang
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} AS builder

ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=1

RUN \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y build-essential libseccomp2:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		apt-get install -y gcc-aarch64-linux-gnu crossbuild-essential-arm64 ; \
	fi

WORKDIR /backend
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY ./pkg ./pkg
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./desktop-extension ./desktop-extension
RUN \
	--mount=type=cache,target=/go/pkg/mod \
	--mount=type=cache,target=/root/.cache/go-build \
	\
	export CGO_ENABLED=1 ; \
	if [ "${TARGETARCH}" = 'arm64' ] ; then \
		export CC=aarch64-linux-gnu-gcc ; \
		export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig ; \
	fi ; \
	GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
		-ldflags "-extldflags '-static'" \
		-o /backend/desktop-extension/bin/ig-service \
		./desktop-extension/ig-service
    #go build -trimpath -ldflags="-s -w" -o bin/ig-service ./desktop-extension/ig-service

# Building Javascript
FROM --platform=$BUILDPLATFORM node:18.9-alpine3.15 AS client-builder
WORKDIR /ui
COPY desktop-extension/ui/package.json /ui/package.json
COPY desktop-extension/ui/package-lock.json /ui/package-lock.json
RUN --mount=type=cache,target=/usr/src/app/.npm \
    npm set cache /usr/src/app/.npm && \
    npm ci
COPY desktop-extension/ui /ui
RUN npm run build


# Building main container
FROM alpine
LABEL org.opencontainers.image.title="inspektor-gadget" \
    org.opencontainers.image.description="Introspecting and debugging Kubernetes applications using eBPF gadgets" \
    org.opencontainers.image.vendor="The Inspektor Gadget authors" \
    com.docker.desktop.extension.api.version=">= 0.2.3" \
    com.docker.extension.screenshots="" \
    com.docker.extension.detailed-description="Inspektor Gadget running as a Docker Desktop Extension" \
    com.docker.extension.publisher-url="https://github.com/inspektor-gadget/inspektor-gadget" \
    com.docker.extension.additional-urls="" \
    com.docker.extension.changelog=""

COPY desktop-extension/docker-compose.yaml .
COPY desktop-extension/metadata.json .
COPY desktop-extension/icon.svg .
COPY desktop-extension/entrypoint.sh .
COPY --from=client-builder /ui/build ui
COPY --from=builder /backend/desktop-extension/bin/ig-service /bin

# For debugging
COPY ig /bin/ig
COPY desktop-extension/ig.sh /bin/ig.sh

ENV HOST_ROOT=/host
ENV INSPEKTOR_GADGET_DOCKER_SOCKETPATH=/host/var/run/docker.sock
ENV INSPEKTOR_GADGET_CONTAINERD_SOCKETPATH=/host/run/containerd/containerd.sock
ENV IG_DESKTOP_EXTENSION_SOCKET=/run/guest-services/albanc_gadget-desktop-extension/ig-desktop-extension.sock
#ENV OCI_RUNTIME_PATH=/proc/1/root/containers/services/docker/rootfs/usr/bin/runc:/proc/1/root/containers/services/docker/lower/usr/bin/runc

RUN mkdir -p /run/guest-services/
CMD /bin/ig-service -socket /run/guest-services/ig-desktop-extension.sock
