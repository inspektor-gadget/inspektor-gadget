ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig
CLANG ?= clang

TEST_ARTIFACTS = \
	empty \
	#

all: $(TEST_ARTIFACTS) legacy_encoding

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
	@sudo $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	#@sudo $(IG) image remove $@:latest

# legacy_encoding is a raw eBPF object (not an OCI image) compiled directly with
# clang: it is a hand-written fixture frozen in the legacy "___" magic-global
# encoding, used by TestLegacyEncodingCompat. It intentionally avoids the
# GADGET_* macros (which now emit ig:* decl tags) and uses only basic types, so
# it needs neither vmlinux.h nor IG_SOURCE_PATH.
.PHONY: legacy_encoding
legacy_encoding:
	@echo "Building $@"
	$(CLANG) -target bpf -g -O2 -Wall -c $@/program.bpf.c -o $@/program.o

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm $$ARTIFACT.tar; \
	done
	rm -f legacy_encoding/program.o
