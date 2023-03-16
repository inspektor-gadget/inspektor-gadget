FROM golang:1.19
# gcc-multilib is needed for <asm/types.h>.
# libelf-dev is needed to compile libbpf.
# lsb-release wget software-properties-common gnupg are needed by llvm.sh script
RUN apt-get update \
	&& apt-get install -y gcc-multilib libelf-dev lsb-release wget software-properties-common gnupg
# install clang 15
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 15 \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-15) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-15) 100
# Let's install libbpf.
RUN git clone -b v0.8.1 https://github.com/libbpf/libbpf.git \
	&& cd libbpf/src \
	&& mkdir build \
	&& OBJDIR=build make install -j
# To avoid hitting this:
# failed to initialize build cache at /.cache/go-build: mkdir /.cache: permission denied
# when run as non root.
ENV GOCACHE=/tmp/
# Create a directory which can be read, written and executed by everyone, this
# avoid trouble when running as non root.
RUN mkdir -m 777 /work
WORKDIR /work
# The resulting docker image should be run with:
# docker run --rm --name ebpf-object-builder --user $(id -u):$(id -g) -v $(pwd):/work name-of-this-image
ENTRYPOINT TARGET=arm64 go generate ./... \
	&& TARGET=amd64 go generate ./...
