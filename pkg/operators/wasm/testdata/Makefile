ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

TEST_ARTIFACTS = \
	fields \
	dataarray \
	badguest \
	params \
	config \
	#

all: $(TEST_ARTIFACTS)

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo IG_SOURCE_PATH=$(realpath $(ROOT_DIR)/../../../..) ig image build -t $@:latest $@
	@sudo ig image export $@:latest $@.tar
	# TODO: This fails with "Error: removing gadget image: unable to reload index:"
	#@sudo ig image remove $@:latest

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm $$ARTIFACT.tar; \
	done
