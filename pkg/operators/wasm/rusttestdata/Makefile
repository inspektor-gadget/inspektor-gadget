ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
IG ?= ig

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

all: $(TEST_ARTIFACTS)

# Mark all test artifact targets as phony
.PHONY: all clean $(TEST_ARTIFACTS)

$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) $(IG) image build -t $@:latest $@
	@sudo $(IG) image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	# @sudo $(IG) image remove $@:latest

clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm -f $$ARTIFACT.tar; \
		sudo rm -rf $$ARTIFACT/target; \
		sudo rm -f $$ARTIFACT/Cargo.lock; \
	done
