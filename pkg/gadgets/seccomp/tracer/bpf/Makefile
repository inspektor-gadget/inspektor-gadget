BPF_ARCH ?= x86

.PHONY: all
all:
	GO111MODULE=on CGO_ENABLED=1 GOOS=linux BPF_ARCH=$(BPF_ARCH) go generate ../

clean:
	rm -f ../seccomp_bpfel.go ../seccomp_bpfel.o
