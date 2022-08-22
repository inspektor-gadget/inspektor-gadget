FROM golang:1.18 AS builder

RUN \
	dpkg --add-architecture arm64 && \
	apt-get update && \
	apt-get install -y gcc-aarch64-linux-gnu build-essential crossbuild-essential-arm64 && \
	apt-get install -y libseccomp2       libseccomp-dev && \
	apt-get install -y libseccomp2:arm64 libseccomp-dev:arm64

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download

ADD . /go/src/github.com/kinvolk/inspektor-gadget
WORKDIR /go/src/github.com/kinvolk/inspektor-gadget

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
		-o local-gadget-${GOOS}-${GOARCH} \
		github.com/kinvolk/inspektor-gadget/cmd/local-gadget
