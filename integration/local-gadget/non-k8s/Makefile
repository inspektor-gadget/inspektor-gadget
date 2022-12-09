# build
build:
	make -C $(shell pwd)/../../.. local-gadget

# test
# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestFilterByContainerName" make -C integration/local-gadget/docker test
test-docker: build
	cp ../../../local-gadget-linux-amd64 local-gadget
	go test -c -o ./local-gadget-docker-integration.test ./...
	sudo ./local-gadget-docker-integration.test -test.v -integration $${INTEGRATION_TESTS_PARAMS}
	rm -f ./local-gadget-docker-integration.test ./local-gadget
