CLANG ?= clang
LLVM_STRIP ?= llvm-strip
EBPF_BUILDER ?= ghcr.io/inspektor-gadget/ebpf-builder

.PHOHY: all
all: testdata_docker

TESTDATA = \
	populate_metadata1.o \
	populate_metadata2.o \
	populate_metadata3.o \
	populate_metadata4.o \
	populate_metadata5.o \
	validate_metadata1.o \
	#

.PHONY: testdata_host
testdata_host: $(TESTDATA)

# build only amd64 variants for testing
%.o: %.bpf.c
	$(CLANG) -target bpf -Wall -g -O2 -D __TARGET_ARCH_x86 -o good.o \
		-I /usr/include/gadget/amd64 -c $< -o $@
	$(LLVM_STRIP) -g $@

.PHONY: testdata_docker
testdata_docker:
	docker run --rm --name testdata-builder --user $(shell id -u):$(shell id -g) \
		-v $(shell pwd):/work $(EBPF_BUILDER) \
		bash -c "cd /work && make testdata_host"
