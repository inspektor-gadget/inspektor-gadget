MINIKUBE_VERSION ?= v1.27.0
KUBERNETES_VERSION ?= v1.24.6
MINIKUBE_DRIVER ?= docker

CONTAINER_RUNTIME ?= docker

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

# minikube

MINIKUBE = $(shell pwd)/bin/minikube-$(MINIKUBE_VERSION)
.PHONY: minikube
minikube:
	mkdir -p bin
	test -e bin/minikube-$(MINIKUBE_VERSION) || \
	(cd bin && curl -Lo ./minikube-$(MINIKUBE_VERSION) https://github.com/kubernetes/minikube/releases/download/$(MINIKUBE_VERSION)/minikube-linux-$(shell go env GOHOSTARCH))
	chmod +x bin/minikube-$(MINIKUBE_VERSION)

# build

build:
	make -C $(shell pwd)/../../.. local-gadget

# clean

.PHONY: clean
clean:
	$(MINIKUBE) delete -p minikube-docker
	$(MINIKUBE) delete -p minikube-containerd
	$(MINIKUBE) delete -p minikube-cri-o
	rm -rf bin

# setup

SETUP_TARGETS = \
	setup-docker \
	setup-containerd \
	setup-cri-o

.PHONY: setup-all
setup-all: $(SETUP_TARGETS) setup

setup: setup-$(CONTAINER_RUNTIME)

.PHONY: phony_explicit
setup-%: minikube
	$(MINIKUBE) status -p minikube-$* -f {{.APIServer}} >/dev/null || \
	$(MINIKUBE) start -p minikube-$* --driver=$(MINIKUBE_DRIVER) --kubernetes-version=$(KUBERNETES_VERSION) --container-runtime=$* --wait=all

# test

TEST_TARGETS = \
	test-docker \
	test-containerd \
	test-cri-o

.PHONY: test-all
test-all: $(TEST_TARGETS) test

test: test-$(CONTAINER_RUNTIME)

# INTEGRATION_TESTS_PARAMS can be used to pass additional parameters locally e.g
# INTEGRATION_TESTS_PARAMS="-test.run TestListContainers" CONTAINER_RUNTIME=containerd make -C integration/local-gadget/k8s test
.PHONY: phony_explicit
test-%: build
	export MINIKUBE_PROFILE=minikube-$* && \
	echo "Checking minikube with profile $${MINIKUBE_PROFILE} is running ..." && \
	$(MINIKUBE) status -p $${MINIKUBE_PROFILE} -f {{.APIServer}} >/dev/null || (echo "Error: $${MINIKUBE_PROFILE} not running, exiting ..." && exit 1) && \
	echo "Preparing minikube with profile $${MINIKUBE_PROFILE} for testing ..." && \
	$(MINIKUBE) cp ../../../local-gadget-linux-amd64 $${MINIKUBE_PROFILE}:/bin/local-gadget >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/local-gadget && \
	go test -c -o local-gadget-integration.test ./... && \
	$(MINIKUBE) cp local-gadget-integration.test $${MINIKUBE_PROFILE}:/bin/local-gadget-integration.test >/dev/null && \
	$(MINIKUBE) ssh sudo chmod +x /bin/local-gadget-integration.test && \
	rm local-gadget-integration.test && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /var/lib/minikube/binaries/$(KUBERNETES_VERSION)/kubectl /bin/kubectl" && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo ln -sf /etc/kubernetes/admin.conf /root/.kube/config" && \
	echo "Running test in minikube with profile $${MINIKUBE_PROFILE} ..." && \
	$(MINIKUBE) -p $${MINIKUBE_PROFILE} ssh "sudo local-gadget-integration.test -test.v -integration -container-runtime $* $${INTEGRATION_TESTS_PARAMS}"
