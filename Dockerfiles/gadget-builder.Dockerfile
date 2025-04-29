ARG CLANG_LLVM_VERSION=18
ARG BPFTOOL_VERSION=v7.3.0
ARG LIBBPF_VERSION=v1.3.0

# Args need to be redefined on each stage
# https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact

FROM golang:1.24.2@sha256:8131d99bd9bdf38a3b9720c23c3d21f40d65137d4b2fd2eccab20e7ab7b5dee4 AS builder
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

# We use Go version >1.24 here for the WASM layers, because it is the first version to support exporting functions
FROM golang:1.24.2@sha256:8131d99bd9bdf38a3b9720c23c3d21f40d65137d4b2fd2eccab20e7ab7b5dee4
ARG CLANG_LLVM_VERSION
# libc-dev is needed for various headers, among others
# /usr/include/arch-linux-gnu/asm/types.h.
# We make clang aware of these files through CFLAGS in Makefile.
# lsb-release wget software-properties-common gnupg are needed by llvm.sh script
# xz-utils is needed by btfgen makefile
RUN apt-get update \
	&& apt-get install -y libc-dev lsb-release wget gnupg xz-utils software-properties-common

# Install clang
## Get the installation script and remove the installation line
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sed -i '/apt-get install -y \$PKG/d' ./llvm.sh
## Now we can precisly install the packages we actually need instead of installing everything
RUN ./llvm.sh $CLANG_LLVM_VERSION && apt-get install -y clang-$CLANG_LLVM_VERSION llvm-$CLANG_LLVM_VERSION clang-format-$CLANG_LLVM_VERSION \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang-format clang-format $(which clang-format-$CLANG_LLVM_VERSION) 100

COPY --from=builder /usr/include/bpf /usr/include/bpf
COPY --from=builder /usr/local/bin/bpftool /usr/local/bin/bpftool

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
