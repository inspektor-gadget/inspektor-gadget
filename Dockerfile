# Builder image for bpftool

FROM ubuntu:18.04 as bpftool-build
RUN apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
    gpg gpg-agent libelf-dev libmnl-dev libc6-dev-i386 iptables libgcc-5-dev \
    bash-completion binutils binutils-dev ca-certificates make git curl \
    ca-certificates xz-utils gcc git pkg-config bison flex build-essential && \
apt-get purge --auto-remove && \
apt-get clean

WORKDIR /tmp

RUN \
git clone --depth 1 -b alban/bpftool-create-map-of-map https://github.com/kinvolk/linux.git && \
cd linux/tools/bpf/bpftool/ && \
sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool

# Builder image for golang
FROM golang:alpine as golang-build
ENV GOPATH /go
WORKDIR /go/src/github.com/kinvolk/k8s-labels-to-bpf
ADD . /go/src/github.com/kinvolk/k8s-labels-to-bpf
RUN go build cmd/k8s-labels-to-bpf/k8s-labels-to-bpf.go

# Builder image for tools
FROM busybox as tools-build
RUN wget https://storage.googleapis.com/kubernetes-release/release/v1.13.4/bin/linux/amd64/kubectl
RUN chmod +x /kubectl

# Main image
FROM amd64/alpine:3.8 as base
RUN apk add jq
ENV HOST_PROC /hostproc
ADD scripts /bin
COPY --from=bpftool-build /tmp/linux/tools/bpf/bpftool/bpftool /bin
COPY --from=golang-build /go/src/github.com/kinvolk/k8s-labels-to-bpf/k8s-labels-to-bpf /bin
COPY --from=tools-build /kubectl /bin
CMD ["/bin/sh"]
