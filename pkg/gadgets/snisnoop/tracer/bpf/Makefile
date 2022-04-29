# We need <asm/types.h> and depending on Linux distributions, it is installed
# at different paths:
#
# * Ubuntu, package linux-libc-dev:
#   /usr/include/x86_64-linux-gnu/asm/types.h
#
# * Fedora, package kernel-headers
#   /usr/include/asm/types.h
#
# Since Ubuntu does not install it in a standard path, add a compiler flag for
# it.
CLANG_OS_FLAGS=
ifeq ($(shell grep -oP '^NAME="\K\w+(?=")' /etc/os-release), Ubuntu)
	CLANG_OS_FLAGS="-I/usr/include/$(shell uname -m)-linux-gnu"
endif

BPF_ARCH ?= x86

.PHONY: all
all:
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux CLANG_OS_FLAGS=$(CLANG_OS_FLAGS) BPF_ARCH=$(BPF_ARCH) go generate ../

clean:
	rm -f ../snisnoop_bpfel.go ../snisnoop_bpfel.o
