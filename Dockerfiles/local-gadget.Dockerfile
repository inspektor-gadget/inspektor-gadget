FROM ghcr.io/inspektor-gadget/local-gadget-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget

ARG GOOS=linux
ENV GOOS=${GOOS}

ARG GOARCH=amd64
ENV GOARCH=${GOARCH}

ARG VERSION=undefined
ENV VERSION=${VERSION}

RUN \
	export CGO_ENABLED=1 ; \
	if [ "${GOOS}-${GOARCH}" != "linux-amd64" ] ; then \
		export CC=aarch64-linux-gnu-gcc ; \
		export PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig ; \
	fi ; \
	go build \
		-ldflags "-X main.version=${VERSION} -extldflags '-static'" \
		-tags 'withebpf' \
		-o local-gadget-${GOOS}-${GOARCH} \
		github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget
