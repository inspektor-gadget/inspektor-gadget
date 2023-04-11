FROM golang:1.20

RUN \
	dpkg --add-architecture arm64 && \
	apt-get update && \
	apt-get install -y gcc-aarch64-linux-gnu build-essential crossbuild-essential-arm64 && \
	apt-get install -y libseccomp2       libseccomp-dev && \
	apt-get install -y libseccomp2:arm64 libseccomp-dev:arm64

ONBUILD COPY go.mod go.sum /cache/
ONBUILD RUN cd /cache && go mod download
ONBUILD ADD . /go/src/github.com/inspektor-gadget/inspektor-gadget
