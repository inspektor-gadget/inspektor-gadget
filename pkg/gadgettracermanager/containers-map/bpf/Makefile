BPF_ARCH ?= x86

.PHONY: all
all: containers-map.o

PKG_DIR=../../..

containers-map.o: containers-map.c
	clang -Werror -I$(PKG_DIR)/$(BPF_ARCH) -I$(PKG_DIR) -target bpf -O2 -g -c -x c $< -o $@

clean:
	rm -f containers-map.o
