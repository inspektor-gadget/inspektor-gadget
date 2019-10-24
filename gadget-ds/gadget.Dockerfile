# Builder: traceloop

FROM docker.io/kinvolk/traceloop:alban-pidns as traceloop

# Builder: bpftool

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
git clone --depth 1 -b alban/bpftool-all https://github.com/kinvolk/linux.git && \
cd linux/tools/bpf/bpftool/ && \
sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool && \
cp /tmp/linux/tools/bpf/bpftool/bpftool /bin/bpftool

# Builder: runc

FROM ubuntu:18.04 as runc-build
ENV GOPATH /go
ENV ORGDIR /go/src/github.com/opencontainers/
ENV BUILDDIR /go/src/github.com/opencontainers/runc
RUN \
apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
	ca-certificates git build-essential golang \
	pkg-config libseccomp-dev && \
mkdir -p $ORGDIR && \
cd $ORGDIR && \
git clone --depth 1 -b alban/static-hooks https://github.com/kinvolk/runc.git && \
cd $BUILDDIR && \
go get -u ./... && \
make COMMIT_NO= BUILDTAGS="seccomp selinux apparmor" && \
cp runc /bin/runc-static-hooks

# Builder: cgroupid

FROM kinvolk/cgroupid as cgroupid

# Builder: kubectl

FROM ubuntu:18.04 as kubectl-get
RUN \
apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
	ca-certificates curl && \
curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl && \
chmod +x kubectl && \
cp kubectl /bin/

# Main gadget image

FROM docker.io/kinvolk/bcc:latest
RUN apt-get update && apt-get install -y \
  curl

COPY --from=bpftool-build /bin/bpftool /bin/bpftool
COPY --from=traceloop /bin/traceloop /bin/traceloop
COPY --from=cgroupid /bin/cgroupid /bin/cgroupid
COPY --from=runc-build /bin/runc-static-hooks /bin/runc-static-hooks
COPY --from=kubectl-get /bin/kubectl /bin/kubectl
COPY files/runc-hook-prestart.sh /bin/runc-hook-prestart.sh
COPY files/runc-hook-prestart-create-maps.sh /bin/runc-hook-prestart-create-maps.sh
COPY files/gadget-node-install.sh /bin/gadget-node-install.sh
COPY files/gadget-node-health-check.sh /bin/gadget-node-health-check.sh
COPY files/bcck8s /opt/bcck8s

