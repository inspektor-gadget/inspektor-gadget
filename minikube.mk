MINIKUBE_VERSION ?= v1.29.0
KUBERNETES_VERSION ?= v1.24.6
MINIKUBE_DRIVER ?= docker

PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
MINIKUBE_DIR ?= $(PROJECT_DIR)/bin/minikube

CONTAINER_RUNTIME ?= docker

# make does not allow implicit rules (with '%') to be phony so let's use
# the 'phony_explicit' dependency to make implicit rules inherit the phony
# attribute
.PHONY: phony_explicit
phony_explicit:

# minikube

MINIKUBE = $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION)
.PHONY: minikube-install
minikube-install:
	mkdir -p $(MINIKUBE_DIR)
	test -e $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION) || \
	(cd $(MINIKUBE_DIR) && curl -Lo ./minikube-$(MINIKUBE_VERSION) https://github.com/kubernetes/minikube/releases/download/$(MINIKUBE_VERSION)/minikube-linux-$(shell go env GOHOSTARCH))
	chmod +x $(MINIKUBE_DIR)/minikube-$(MINIKUBE_VERSION)

# clean

.PHONY: minikube-clean
minikube-clean:
	$(MINIKUBE) delete -p minikube-docker
	$(MINIKUBE) delete -p minikube-containerd
	$(MINIKUBE) delete -p minikube-cri-o
	rm -rf $(MINIKUBE_DIR)

# start

MINIKUBE_START_TARGETS = \
	minikube-start-docker \
	minikube-start-containerd \
	minikube-start-cri-o

.PHONY: minikube-start-all
minikube-start-all: $(MINIKUBE_START_TARGETS)

minikube-start: minikube-start-$(CONTAINER_RUNTIME)

.PHONY: phony_explicit
minikube-start-%: minikube-install
	$(MINIKUBE) status -p minikube-$* -f {{.APIServer}} >/dev/null || \
	$(MINIKUBE) start -p minikube-$* --driver=$(MINIKUBE_DRIVER) --kubernetes-version=$(KUBERNETES_VERSION) --container-runtime=$* --wait=all $${MINIKUBE_PARAMS}
	$(MINIKUBE) profile minikube-$*

