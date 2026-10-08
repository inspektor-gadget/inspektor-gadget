ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig
SUDO ?= sudo

TEST_ARTIFACTS = \
	dataemit \
	dataarray \
	fields \
	params \
	config \
	map \
	mapofmap \
	perf \
	syscall \
	kallsyms \
	filtering \
	baderrptr \
	badguest \
	noretval \

all: $(TEST_ARTIFACTS)

# Mark all test artifact targets as phony
.PHONY: all clean $(TEST_ARTIFACTS)

$(TEST_ARTIFACTS):
	@echo "Building $@"
	@$(SUDO) IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
	@$(SUDO) $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	# @sudo $(IG) image remove $@:latest

clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		$(SUDO) rm -f $$ARTIFACT.tar; \
		$(SUDO) rm -rf $$ARTIFACT/target; \
		$(SUDO) rm -f $$ARTIFACT/Cargo.lock; \
	done
