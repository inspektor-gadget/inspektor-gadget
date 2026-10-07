# The user flag is only needed when using rootfull docker.
# Users with rootless docker and/or podman can set this variable on call to
# true to avoid problems.
ENABLE_DOCKER_ROOTLESS ?= false
DOCKER_USER_FLAG ?= $(if $(filter true,$(ENABLE_DOCKER_ROOTLESS)),,--user $(shell id -u):$(shell id -g))
