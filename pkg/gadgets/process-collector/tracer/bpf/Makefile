.PHONY: all
all: process-collector.o process-collector-with-filter.o

PKG_DIR=../../../..

process-collector.o: process-collector.c
	clang -I$(PKG_DIR) -target bpf -O2 -g -c -x c $< -o $@

process-collector-with-filter.o: process-collector.c
	clang -I$(PKG_DIR) -target bpf -O2 -g -c -x c $< -o $@ -DWITH_FILTER=1
