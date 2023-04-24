DNSTESTER_IMAGE ?= "ghcr.io/inspektor-gadget/dnstester:latest"
CONTAINER_RUNTIME ?= docker

# build
build:
	make -C $(shell pwd)/../../.. ig


# test

TEST_TARGETS = \
	test-docker

.PHONY: test-all
test-all: $(TEST_TARGETS)

test: test-$(CONTAINER_RUNTIME)

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestFilterByContainerName" make -C integration/ig/non-k8s test-docker
test-%: build
	cp ../../../ig-linux-amd64 ig
	go test -c -o ./ig-docker-integration.test ./...
	sudo ./ig-docker-integration.test -test.v -integration -runtime $* -dnstester-image $(DNSTESTER_IMAGE) $${INTEGRATION_TESTS_PARAMS}
	rm -f ./ig-docker-integration.test ./ig
