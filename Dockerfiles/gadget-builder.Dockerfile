ARG CLANG_LLVM_VERSION=18
ARG BPFTOOL_VERSION=v7.3.0
ARG LIBBPF_VERSION=v1.3.0
ARG GOLANG_VERSION=1.24.2

# Args need to be redefined on each stage
# https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact

FROM debian:bookworm-slim@sha256:4b50eb66f977b4062683ff434ef18ac191da862dbe966961bc11990cf5791a8d AS builder
ARG BPFTOOL_VERSION
ARG LIBBPF_VERSION

RUN apt-get update \
	&& apt-get install -y git make tar wget

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

FROM rust:slim-bullseye@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081 AS rustbuilder

FROM debian:bookworm-slim@sha256:4b50eb66f977b4062683ff434ef18ac191da862dbe966961bc11990cf5791a8d
ARG CLANG_LLVM_VERSION
ARG GOLANG_VERSION
# libc-dev is needed for various headers, among others
# /usr/include/arch-linux-gnu/asm/types.h.
# We make clang aware of these files through CFLAGS in Makefile.
# wget is needed to download the LLVM key and Golang tarball
# lsb-release software-properties-common is needed to add the LLVM repository
# xz-utils is needed by btfgen makefile
# make and git is needed for make ebpf-objects and make clang-format
# clang-format is needed for make clang-format
RUN apt-get update \
	&& apt-get install -y --no-install-recommends libc-dev lsb-release wget xz-utils software-properties-common make git

# Install clang
# Add the keys and repository for the LLVM packages
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && codename=$(lsb_release -cs) \
	# We need to call add-apt-repository twice in debian-bookworm because of a bug: https://github.com/llvm/llvm-project/issues/62475#issuecomment-1579252282
    && add-apt-repository -y "deb http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${CLANG_LLVM_VERSION} main" \
	&& add-apt-repository -y "deb http://apt.llvm.org/${codename}/ llvm-toolchain-${codename}-${CLANG_LLVM_VERSION} main" \
    && apt-get update \
	&& apt-get install -y --no-install-recommends clang-$CLANG_LLVM_VERSION llvm-$CLANG_LLVM_VERSION clang-format-$CLANG_LLVM_VERSION \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang-format clang-format $(which clang-format-$CLANG_LLVM_VERSION) 100

# Install golang
RUN ARCH=$(dpkg --print-architecture) \
	&& wget --quiet https://go.dev/dl/go${GOLANG_VERSION}.linux-${ARCH}.tar.gz && \
	tar -C /usr/local -xzf go${GOLANG_VERSION}.linux-${ARCH}.tar.gz && \
	rm go${GOLANG_VERSION}.linux-${ARCH}.tar.gz && \
	ln -s /usr/local/go/bin/go /usr/local/bin/go && \
	chmod +x /usr/local/go/bin/go

COPY --from=builder /usr/include/bpf /usr/include/bpf
COPY --from=builder /usr/local/bin/bpftool /usr/local/bin/bpftool
COPY --from=rustbuilder /usr/local/cargo /usr/local/.cargo
COPY --from=rustbuilder /usr/local/rustup /usr/local/.rustup

# Add Rust to PATH
ENV PATH="/usr/local/.cargo/bin:/usr/local/.rustup:$PATH"

# Add wasm target
RUN rustup default stable
RUN rustup target add wasm32-wasip1

# To avoid hitting
# 1. failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
# 2. could not create module cache: mkdir /go: permission denied
# when run as non root.
ENV GOCACHE=/tmp/gocache
ENV GOMODCACHE=/tmp/gomodcache

# don't auto-upgrade the gotoolchain
# https://github.com/docker-library/golang/issues/472
ENV GOTOOLCHAIN=local

# Create a directory which can be read, written and executed by everyone, this
# avoid trouble when running as non root.
RUN mkdir -m 777 /work

WORKDIR /work

# Add files used to build containerized gadgets
ADD include /usr/include


