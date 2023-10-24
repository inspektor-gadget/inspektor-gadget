ARG CLANG_LLVM_VERSION=15
ARG LIBBPF_VERSION=v1.2.2
ARG TINYGO_VERSION=0.30.0

# Args need to be redefined on each stage
# https://docs.docker.com/engine/reference/builder/#understand-how-arg-and-from-interact

FROM golang:1.20 as builder
ARG LIBBPF_VERSION

# Let's install libbpf headers
RUN git clone --branch ${LIBBPF_VERSION} --depth 1 https://github.com/libbpf/libbpf.git \
	&& cd libbpf/src && make install_headers

FROM golang:1.20
ARG CLANG_LLVM_VERSION
ARG TINYGO_VERSION
# libc-dev is needed for various headers, among others
# /usr/include/arch-linux-gnu/asm/types.h.
# libc-dev-i386 is needed on amd64 to provide <gnu/stubs-32.h>.
# We make clang aware of these files through CFLAGS in Makefile.
# lsb-release wget software-properties-common gnupg are needed by llvm.sh script
RUN apt-get update \
	&& apt-get install -y libc-dev lsb-release wget software-properties-common gnupg \
	&& if [ "$(dpkg --print-architecture)" = 'amd64' ]; then apt-get install -y libc6-dev-i386; fi
# install clang 15
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh $CLANG_LLVM_VERSION \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-$CLANG_LLVM_VERSION) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-$CLANG_LLVM_VERSION) 100

COPY --from=builder /usr/include/bpf /usr/include/bpf

RUN \
	DEB=tinygo.deb && \
	ARCH=$(dpkg --print-architecture) && \
	wget --quiet https://github.com/tinygo-org/tinygo/releases/download/v${TINYGO_VERSION}/tinygo_${TINYGO_VERSION}_${ARCH}.deb -O $DEB && \
	if [ "${ARCH}" = 'amd64' ] ; then \
		SHA='abcef56b2ae04e27253df409b32d0b7abb5ae76ed493db75b2f80659cbf59363c85919836116780adcad051c652e991dc46fa6ae7cec31a4fa3bdb68d2123621'; \
	elif [ "${ARCH}" = 'arm64' ] ; then \
		SHA='d121940aa1cd366c865f1600c88decf2a9db6891234f738024702891ecff94958848ce6bb3191b3a34250ab7091bc3e35b27cc612d7324f48a4d148869fa306f'; \
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
ADD cmd/common/image/Makefile.build /Makefile
