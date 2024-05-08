ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))

TEST_ARTIFACTS = \
	fields \
	dataarray \
	badguest \
	#

all: $(TEST_ARTIFACTS)

.PHONY: $(TEST_ARTIFACTS)
$(TEST_ARTIFACTS):
	@echo "Building $@"
	@sudo -E IG_EXPERIMENTAL=true \
		INSPEKTOR_GADGET_PATH=$(realpath $(ROOT_DIR)/../../../..) \
		ig image build \
		-t $@:latest \
		$@
	@sudo -E IG_EXPERIMENTAL=true \
		ig image export $@:latest $@.tar
	# This fails with Error: removing gadget image: unable to reload index
	#@sudo -E IG_EXPERIMENTAL=true \
	#	ig image remove $@:latest

.PHONY:
clean:
	for ARTIFACT in $(TEST_ARTIFACTS); do \
		sudo rm $$ARTIFACT.tar; \
	done
