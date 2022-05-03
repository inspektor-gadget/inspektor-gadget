# Dockerfile for Inspektor Gadget container image.
# This image contains CO-RE and BCC-based gadgets. Its base image is the
# BCC image. It's the default image that is deployed in Inspektor Gadget.

ARG BUILDER_IMAGE=ubuntu:20.04

# BCC built from the gadget branch in the kinvolk/bcc fork.
# See BCC section in docs/CONTRIBUTING.md for further details.
ARG BCC="quay.io/kinvolk/bcc:4b74e843ca90ac0b39ebca2685c939f511aa2c11-focal-release"

FROM ${BCC} as bcc
FROM ${BUILDER_IMAGE} as builder

ARG ENABLE_BTFGEN=false
ENV ENABLE_BTFGEN=${ENABLE_BTFGEN}

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git clang-12 \
		software-properties-common libelf-dev pkg-config libseccomp-dev llvm-12 && \
	apt-add-repository -y ppa:longsleep/golang-backports && \
	apt-get update && \
	apt-get install -y golang-1.17 && \
	ln -s /usr/lib/go-1.17/bin/go /bin/go && \
	update-alternatives --install /usr/local/bin/clang clang /usr/bin/clang-12 100 && \
	update-alternatives --install /usr/local/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-12 100

# Install libbpf-dev 0.7.0 from source to be cross-platform.
RUN git clone https://github.com/libbpf/libbpf.git && \
	cd libbpf/src && \
	git checkout v0.7.0 && \
	make -j$(nproc) install

# Download BTFHub files
COPY ./tools /btf-tools
RUN set -ex; mkdir -p /tmp/btfs && \
	if [ "$ENABLE_BTFGEN" = true ]; then \
		cd /btf-tools && \
		./getbtfhub.sh; \
	fi

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget/gadget-container && make gadget-container-deps

# Execute BTFGen
RUN set -ex; \
	if [ "$ENABLE_BTFGEN" = true ]; then \
		cd /btf-tools && \
		BTFHUB=/tmp/btfhub INSPEKTOR_GADGET=/gadget ./btfgen.sh; \
	fi

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/95857527df8d343a054d3754dc3b77c7c8c274c7
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:2059b729c0ac8aa79016dacb06fbdaa1867c1446 as traceloop

# Main gadget image

FROM bcc

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates curl jq wget xz-utils binutils rpm2cpio cpio && \
		rmdir /usr/src && ln -sf /host/usr/src /usr/src && \
		rm -f /etc/localtime && ln -sf /host/etc/localtime /etc/localtime

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/
COPY --from=builder /gadget/gadget-container/bin/networkpolicyadvisor /bin/

COPY gadget-container/gadgets/bcck8s /opt/bcck8s/

COPY --from=traceloop /bin/traceloop /bin/

## Hooks Begins

# OCI
COPY gadget-container/hooks/oci/prestart.sh gadget-container/hooks/oci/poststop.sh /opt/hooks/oci/
COPY --from=builder /gadget/gadget-container/bin/ocihookgadget /opt/hooks/oci/

# cri-o
COPY gadget-container/hooks/crio/gadget-prestart.json gadget-container/hooks/crio/gadget-poststop.json /opt/hooks/crio/

# nri
COPY --from=builder /gadget/gadget-container/bin/nrigadget /opt/hooks/nri/
COPY gadget-container/hooks/nri/conf.json /opt/hooks/nri/

## Hooks Ends

# BTF files
COPY --from=builder /tmp/btfs /btfs/

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm -f /var/run
