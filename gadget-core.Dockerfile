# Dockerfile for Inspektor Gadget CO-RE container image gadgets.
# This is a reduced gadget container image that supports only the CO-RE
# implementation of the gadgets, i.e, it doesn't depend on BCC. This
# image is much smaller than the image built with gadget.bcc.Dockerfile
# and is designed to be used on systems that support BTF
# (CONFIG_DEBUG_INFO_BTF).

ARG BUILDER_IMAGE=ubuntu:20.04
ARG BASE_IMAGE=alpine:3.14

# Prepare and build gadget artifacts in a container
FROM ${BUILDER_IMAGE} as builder

ARG ENABLE_BTFGEN=false
ENV ENABLE_BTFGEN=${ENABLE_BTFGEN}

RUN set -ex; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get update && \
	apt-get install -y gcc make ca-certificates git \
		software-properties-common libelf-dev pkg-config libseccomp-dev && \
	apt-add-repository -y ppa:longsleep/golang-backports && \
	apt-get update && \
	apt-get install -y golang-1.18 && \
	ln -s /usr/lib/go-1.18/bin/go /bin/go

# Install libbpf-dev 0.7.0 from source to be cross-platform.
RUN git clone --branch v0.7.0 --depth 1 https://github.com/libbpf/libbpf.git && \
	make -j$(nproc) -C libbpf/src install

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
		cd /gadget && \
		make btfgen BPFTOOL=/tmp/btfhub/tools/bin/bpftool.x86_64 \
			BTFHUB_ARCHIVE=/tmp/btfhub-archive/ OUTPUT=/tmp/btfs/ -j$(nproc); \
	fi

# Main gadget image
FROM ${BASE_IMAGE}

# install runtime dependencies  according to the package manager
# available on the base image
RUN set -ex; \
	if command -v tdnf; then \
		tdnf install -y libseccomp wget curl; \
	elif command -v yum; then \
		yum install -y libseccomp wget curl; \
	elif command -v apt-get; then \
		apt-get update && \
		apt-get install -y seccompwget curl ; \
	elif command -v apk; then \
		apk add gcompat libseccomp bash wget curl ; \
	fi && \
	rmdir /usr/src || true && ln -sf /host/usr/src /usr/src && \
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
COPY --from=builder /tmp/btfs /btfs/

# Mitigate https://github.com/kubernetes/kubernetes/issues/106962.
RUN rm -f /var/run
