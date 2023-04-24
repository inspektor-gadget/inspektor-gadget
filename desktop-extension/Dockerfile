# Building Golang
FROM golang:1.19-alpine AS builder
ENV CGO_ENABLED=0
WORKDIR /backend
COPY service/go.* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY service/. .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w" -o bin/ig-service

# Building Javascript
FROM --platform=$BUILDPLATFORM node:18.9-alpine3.15 AS client-builder
WORKDIR /ui
COPY ui/package.json /ui/package.json
COPY ui/package-lock.json /ui/package-lock.json
RUN --mount=type=cache,target=/usr/src/app/.npm \
    npm set cache /usr/src/app/.npm && \
    npm ci
COPY ui /ui
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

COPY docker-compose.yaml .
COPY metadata.json .
COPY icon.svg .
COPY --from=client-builder /ui/build ui
COPY bin/ig-service /bin/ig-service
COPY --from=builder /backend/bin/ig-service /

CMD /bin/ig-service -socket /run/guest-services/ig-desktop-extension.sock
