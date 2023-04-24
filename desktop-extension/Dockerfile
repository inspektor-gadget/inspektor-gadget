FROM alpine
LABEL org.opencontainers.image.title="inspektor-gadget" \
    org.opencontainers.image.description="Introspecting and debugging Kubernetes applications using eBPF gadgets" \
    org.opencontainers.image.vendor="The Inspektor Gadget authors" \
    com.docker.desktop.extension.api.version=">= 0.2.3" \
    com.docker.extension.screenshots="" \
    com.docker.extension.detailed-description="Inspektor Gadget running as a Docker Desktop Extension" \
    com.docker.extension.publisher-url="https://github.com/inspektor-gadget/inspektor-gadget" \
    com.docker.extension.additional-urls="" \
    com.docker.extension.changelog=""

COPY docker-compose.yaml .
COPY metadata.json .
COPY icon.svg .
COPY ui ui
COPY bin/service /bin/service
