ARG CLANG_LLVM_VERSION=18
ARG BPFTOOL_VERSION=v7.3.0
ARG LIBBPF_VERSION=v1.3.0
ARG TINYGO_VERSION=0.34.0

# Args need to be redefined on each stage
# https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact

FROM golang:1.24rc2@sha256:a5ddeaeeec69e764a7a86c6063ceabb4ab0261a448a173ba3ad0dde7b93524d6 AS builder
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

FROM golang:1.24rc2@sha256:a5ddeaeeec69e764a7a86c6063ceabb4ab0261a448a173ba3ad0dde7b93524d6
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
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh $CLANG_LLVM_VERSION all \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang-format clang-format $(which clang-format-$CLANG_LLVM_VERSION) 100

COPY --from=builder /usr/include/bpf /usr/include/bpf
COPY --from=builder /usr/local/bin/bpftool /usr/local/bin/bpftool

# Install tinygo
RUN \
	DEB=tinygo.deb && \
	ARCH=$(dpkg --print-architecture) && \
	wget --quiet https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_${ARCH}.deb -O $DEB && \
	if [ "${ARCH}" = 'amd64' ] ; then \
		SHA='fdfa65973b7e17545ceef12a2b361f51989d7459eb8111833b197352915c2092abc540daa944b0fa07f99fad45917517ff285ad6e1e2e96cb622458d7c058934'; \
	elif [ "${ARCH}" = 'arm64' ] ; then \
		SHA='1ef5653014eb44302b698205f93f9fe212a5c35fb88547e2756c167c858aac154b70c1ac01a69f9b65d085742dd8547df52ca91035c3ecd0f13b6e9d514509bc'; \
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
