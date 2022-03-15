.PHONY: all
all: graph.o

# See Linux' Makefile: when ARCH is i386 or x86_64, then SRCARCH is x86
# It needs to match tests in bpf/bpf_tracing.h
SRCARCH ?= x86

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

PKG_DIR=../../../..

graph.o: graph.c
	clang -Werror -I$(PKG_DIR) $(CLANG_OS_FLAGS) -target bpf -O2 -g -c -x c $< -o $@ \
		-D__KERNEL__ -D__TARGET_ARCH_$(SRCARCH)

clean:
	rm -f graph.o
