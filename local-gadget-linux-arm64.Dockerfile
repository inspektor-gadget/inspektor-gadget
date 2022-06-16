FROM golang:1.18 AS builder

RUN \
	dpkg --add-architecture arm64 && \
	apt-get update && \
	apt-get install -y gcc-aarch64-linux-gnu build-essential crossbuild-essential-arm64 && \
	apt-get install -y libseccomp2:arm64 libseccomp-dev:arm64

COPY go.mod go.sum /cache/
RUN cd /cache && go mod download

ADD . /go/src/github.com/kinvolk/inspektor-gadget
WORKDIR /go/src/github.com/kinvolk/inspektor-gadget

RUN \
	CGO_ENABLED=1 \
	CC=aarch64-linux-gnu-gcc \
	GOOS=linux GOARCH=arm64 \
	PKG_CONFIG_PATH=/usr/lib/aarch64-linux-gnu/pkgconfig \
	go build \
	-tags withebpf \
	-o local-gadget-linux-arm64 \
	github.com/kinvolk/inspektor-gadget/cmd/local-gadget
