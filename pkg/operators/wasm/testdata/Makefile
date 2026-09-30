ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig
SUDO ?= sudo

TEST_ARTIFACTS = \
	fields \
	dataarray \
	dataemit \
	badguest \
	baderrptr \
	noretval \
	params \
	config \
	map \
	mapofmap \
	syscall \
	perf \
	kallsyms \
	filtering \
	#

all: $(TEST_ARTIFACTS)

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@$(SUDO) IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
	@$(SUDO) $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	#@sudo $(IG) image remove $@:latest

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		$(SUDO) rm $$ARTIFACT.tar; \
	done
