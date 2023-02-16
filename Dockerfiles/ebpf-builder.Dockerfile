FROM golang:1.19
# clang and llvm are needed by bpf2go.
# gcc-multilib is needed for <asm/types.h>.
# libelf-dev is needed to compile libbpf.
RUN apt-get update \
	&& apt-get install -y clang-11 llvm-11 gcc-multilib libelf-dev \
	&& update-alternatives --install /usr/local/bin/llvm-strip llvm-strip $(which llvm-strip-11) 100 \
	&& update-alternatives --install /usr/local/bin/clang clang $(which clang-11) 100
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
