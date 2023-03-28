DNSTESTER_IMAGE ?= "ghcr.io/inspektor-gadget/dnstester:latest"

# build
build:
	make -C $(shell pwd)/../../.. ig

# test
# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestFilterByContainerName" make -C integration/ig/non-k8s test-docker
test-docker: build
	cp ../../../ig-linux-amd64 ig
	go test -c -o ./ig-docker-integration.test ./...
	sudo ./ig-docker-integration.test -test.v -integration -dnstester-image $(DNSTESTER_IMAGE) $${INTEGRATION_TESTS_PARAMS}
	rm -f ./ig-docker-integration.test ./ig
