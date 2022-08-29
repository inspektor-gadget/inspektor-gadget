# Dockerfile for Inspektor Gadget container image.
# This image contains CO-RE and BCC-based gadgets. Its base image is the
# BCC image. It's the default image that is deployed in Inspektor Gadget.

ARG BUILDER_IMAGE=debian:bullseye

# BCC built from the gadget branch in the kinvolk/bcc fork.
# See BCC section in docs/CONTRIBUTING.md for further details.
ARG BCC="quay.io/kinvolk/bcc:7d56a6f6920826a62a3cc0dc7fc302bf3cdf2618-focal-release"

FROM ${BCC} as bcc
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG ENABLE_BTFGEN=false
ENV ENABLE_BTFGEN=${ENABLE_BTFGEN}

ARG TARGETARCH
# We need a cross compiler and libraries for TARGETARCH due to CGO.
RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git && \
	echo 'deb http://deb.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list && \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y golang-1.18 libelf-dev:${TARGETARCH} \
		pkg-config:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	ln -s /usr/lib/go-1.18/bin/go /bin/go && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		apt-get install -y gcc-aarch64-linux-gnu; \
	fi

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
RUN cd /gadget/gadget-container && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		export CC=aarch64-linux-gnu-gcc; \
	fi; \
	make -j$(nproc) TARGET_ARCH=${TARGETARCH} gadget-container-deps

# Execute BTFGen
RUN set -ex; \
	if [ "$ENABLE_BTFGEN" = true ]; then \
		cd /gadget && \
		make btfgen BPFTOOL=/tmp/btfhub/tools/bin/bpftool.x86_64 \
			BTFHUB_ARCHIVE=/tmp/btfhub-archive/ OUTPUT=/tmp/btfs/ -j$(nproc); \
	fi

# Builder: traceloop

# traceloop built from:
# https://github.com/kinvolk/traceloop/commit/95857527df8d343a054d3754dc3b77c7c8c274c7
# See:
# - https://github.com/kinvolk/traceloop/actions
# - https://hub.docker.com/r/kinvolk/traceloop/tags

FROM docker.io/kinvolk/traceloop:20211109004128958575 as traceloop

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
