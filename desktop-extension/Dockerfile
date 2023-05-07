# Building Golang
FROM golang:1.19-alpine AS builder
ENV CGO_ENABLED=0
WORKDIR /backend
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY ./pkg ./pkg
COPY ./cmd ./cmd
COPY ./internal ./internal
COPY ./desktop-extension ./desktop-extension
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    pwd;ls -l ;go build -trimpath -ldflags="-s -w" -o bin/ig-service ./desktop-extension/ig-service

# Building Javascript
FROM --platform=$BUILDPLATFORM node:18.9-alpine3.15 AS client-builder
WORKDIR /ui
COPY desktop-extension/ui/package.json /ui/package.json
COPY desktop-extension/ui/package-lock.json /ui/package-lock.json
RUN --mount=type=cache,target=/usr/src/app/.npm \
    npm set cache /usr/src/app/.npm && \
    npm ci
COPY desktop-extension/ui /ui
RUN npm run build


# Building main container
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

COPY desktop-extension/docker-compose.yaml .
COPY desktop-extension/metadata.json .
COPY desktop-extension/icon.svg .
COPY --from=client-builder /ui/build ui
#COPY desktop-extension/bin/ig-service /bin/ig-service
COPY --from=builder /backend/desktop-extension/bin/ig-service /bin

ENV HOST_ROOT=/host
RUN mkdir -p /run/guest-services/
CMD /bin/ig-service -socket /run/guest-services/ig-desktop-extension.sock
