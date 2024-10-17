ARG CLANG_LLVM_VERSION=15
ARG BPFTOOL_VERSION=v7.3.0
ARG LIBBPF_VERSION=v1.3.0
ARG TINYGO_VERSION=0.31.2

# Args need to be redefined on each stage
# https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact

FROM golang:1.22.8@sha256:ed01175ba5c08d20d824d3a3387ec2e392827e1116212ff0ab3e6db7b7de63ba AS builder
ARG BPFTOOL_VERSION
ARG LIBBPF_VERSION

# Let's install libbpf headers
RUN git clone --branch ${LIBBPF_VERSION} --depth 1 https://github.com/libbpf/libbpf.git \
	&& cd libbpf/src && make install_headers

	# Install bpftool
RUN \
	ARCH=$(dpkg --print-architecture) && \
	wget --quiet https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-${ARCH}.tar.gz && \
	wget --quiet https://github.com/libbpf/bpftool/releases/download/${BPFTOOL_VERSION}/bpftool-${BPFTOOL_VERSION}-${ARCH}.tar.gz.sha256sum && \
	echo $(cat bpftool-${BPFTOOL_VERSION}-${ARCH}.tar.gz.sha256sum) | sha256sum -c && \
	tar -C /usr/local/bin -xzf bpftool-${BPFTOOL_VERSION}-${ARCH}.tar.gz && \
	chmod +x /usr/local/bin/bpftool

FROM golang:1.22.8@sha256:ed01175ba5c08d20d824d3a3387ec2e392827e1116212ff0ab3e6db7b7de63ba
ARG CLANG_LLVM_VERSION
ARG TINYGO_VERSION
# libc-dev is needed for various headers, among others
# /usr/include/arch-linux-gnu/asm/types.h.
# libc-dev-i386 is needed on amd64 to provide <gnu/stubs-32.h>.
# We make clang aware of these files through CFLAGS in Makefile.
# lsb-release wget software-properties-common gnupg are needed by llvm.sh script
# xz-utils is needed by btfgen makefile
RUN apt-get update \
	&& apt-get install -y libc-dev lsb-release wget software-properties-common gnupg xz-utils \
	&& if [ "$(dpkg --print-architecture)" = 'amd64' ]; then apt-get install -y libc6-dev-i386; fi
# Install clang 15
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh $CLANG_LLVM_VERSION \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-$CLANG_LLVM_VERSION) 100

COPY --from=builder /usr/include/bpf /usr/include/bpf
COPY --from=builder /usr/local/bin/bpftool /usr/local/bin/bpftool

# Install tinygo
RUN \
	DEB=tinygo.deb && \
	ARCH=$(dpkg --print-architecture) && \
	wget --quiet https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_${ARCH}.deb -O $DEB && \
	if [ "${ARCH}" = 'amd64' ] ; then \
		SHA='315ecb11bdf20813f9f9e04e875b1e1dbedfec150284782db50f747b1d3a477b8eeebb686fe32995bddfc1d6b4db2135f3d15ddeabcffc1c93884b0d11ad1bc9'; \
	elif [ "${ARCH}" = 'arm64' ] ; then \
		SHA='d41ded645a2a7cce466a4228d7308a56fc8503759b67aff38cb044ed7636a98e5d83f11b312fcf5f1508c90d5ac5e38ca3e3ae89f866467dc406fbd0fd700ae1'; \
	else \
		echo "${ARCH} is not supported" 2>&1 ; \
		exit 1; \
	fi && \
	echo $SHA $DEB | sha512sum -c && \
	dpkg -i $DEB && \
	rm -f $DEB

# To avoid hitting this:
# failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
# when run as non root.
ENV GOCACHE=/tmp/
# Create a directory which can be read, written and executed by everyone, this
# avoid trouble when running as non root.
RUN mkdir -m 777 /work
WORKDIR /work

# Add files used to build containerized gadgets
ADD include /usr/include
