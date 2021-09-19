.PHONY: all
all: signal.o

PKG_DIR=../../../..

# See Linux' Makefile: when ARCH is i386 or x86_64, then SRCARCH is x86
# It needs to match tests in bpf/bpf_tracing.h
SRCARCH ?= x86

signal.o: signal.c
	clang -Werror -I$(PKG_DIR) -target bpf -O2 -g -c -x c $< -o $@ \
		-D__KERNEL__ -D__TARGET_ARCH_$(SRCARCH)
