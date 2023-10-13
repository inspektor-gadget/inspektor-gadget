# Dockerfile for the kubectl-gadget plugin.
# This image is useful for cases where downloading and running a binary
# is not possible or is complicated. In this cases, this container image
# provides an alternative to download and run kubectl-gadget.
# Since the plugin is a statically compiled golang application, any base
# image is valid, even scratch. Alpine is used by default as a tradeoff
# between size and tools available in the image.

ARG BUILDER_IMAGE=golang:1.20-bullseye
ARG BASE_IMAGE=alpine:3.18

FROM ${BUILDER_IMAGE} as builder

# Cache go modules so they won't be downloaded at each build
COPY go.mod go.sum /gadget/
RUN cd /gadget && go mod download

# default image that will be used in the deploy command
ARG CONTAINER_REPO="ghcr.io/inspektor-gadget/inspektor-gadget"
ENV CONTAINER_REPO=${CONTAINER_REPO}

ARG IMAGE_TAG
ENV IMAGE_TAG=${IMAGE_TAG}

# This COPY is limited by .dockerignore
COPY ./ /gadget
RUN cd /gadget && make kubectl-gadget

FROM ${BASE_IMAGE}

LABEL org.opencontainers.image.source=https://github.com/inspektor-gadget/inspektor-gadget
LABEL org.opencontainers.image.title="Inspektor Gadget kubectl-gadget tool"
LABEL org.opencontainers.image.description="Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. This image only includes the kubectl-gadget binary, a kubectl plugin for Inspektor Gadget."
LABEL org.opencontainers.image.documentation="https://inspektor-gadget.io/docs"
LABEL org.opencontainers.image.licenses=Apache-2.0

COPY --from=builder /gadget/kubectl-gadget /bin/kubectl-gadget
