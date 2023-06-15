# Dockerfile for Inspektor Gadget container image.
# This image contains CO-RE and BCC-based gadgets. Its base image is the
# BCC image. It's the default image that is deployed in Inspektor Gadget.

ARG BUILDER_IMAGE=golang:1.19-bullseye

# BCC built from the gadget branch in the kinvolk/bcc fork.
# See BCC section in docs/devel/CONTRIBUTING.md for further details.
ARG BCC="quay.io/kinvolk/bcc:gadget"

# bpftrace upstream image
ARG BPFTRACE="ghcr.io/inspektor-gadget/bpftrace"

FROM ${BCC} as bcc
FROM ${BPFTRACE} as bpftrace
FROM --platform=${BUILDPLATFORM} ${BUILDER_IMAGE} as builder

ARG TARGETARCH
# We need a cross compiler and libraries for TARGETARCH due to CGO.
RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	dpkg --add-architecture ${TARGETARCH} && \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git libelf-dev:${TARGETARCH} \
		pkg-config:${TARGETARCH} libseccomp-dev:${TARGETARCH} && \
	if [ ${TARGETARCH} = 'arm64' ]; then \
		apt-get install -y gcc-aarch64-linux-gnu; \
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

# Main gadget image

FROM bcc

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y --no-install-recommends \
		ca-certificates jq wget xz-utils binutils socat && \
	rmdir /usr/src && ln -sf /host/usr/src /usr/src && \
	rm -f /etc/localtime && ln -sf /host/etc/localtime /etc/localtime

COPY gadget-container/entrypoint.sh gadget-container/cleanup.sh /

COPY --from=builder /gadget/gadget-container/bin/gadgettracermanager /bin/

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
COPY hack/btfs /btfs/

COPY --from=bpftrace /usr/bin/bpftrace /usr/bin/bpftrace

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm -f /var/run

ENV GADGET_IMAGE_FLAVOUR=default
