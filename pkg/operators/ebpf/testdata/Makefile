ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig

TEST_ARTIFACTS = \
	empty \
	#

all: $(TEST_ARTIFACTS)

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
	@sudo $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	#@sudo $(IG) image remove $@:latest

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm $$ARTIFACT.tar; \
	done

# Architecture-independent instruction fixtures for policy tests. Keep the
# objects checked in so the pure tests do not require clang, root, or Docker.
CLANG ?= clang
.PHONY: policy-fixtures
policy-fixtures: policy.bpf.o policy-kfunc.bpf.o policy-callback.bpf.o

%.bpf.o: %/program.bpf.c
	$(CLANG) -target bpfel -O2 -g -Wall -Werror -ffile-prefix-map=$(CURDIR)=. -c $< -o $@
