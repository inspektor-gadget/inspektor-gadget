# IMAGE=docker.io/albanc/gadget-desktop-extension TAG=0.12 make push-extension

IMAGE?=localhost:5000/gadget-desktop-extension
TAG?=latest

BUILDER=buildx-multi-arch

STATIC_FLAGS=CGO_ENABLED=0
LDFLAGS="-s -w"
GO_BUILD=$(STATIC_FLAGS) go build -trimpath -ldflags=$(LDFLAGS)

.PHONY: bin
bin:
	mkdir -p bin
	$(GO_BUILD) -o bin/ig-service ./ig-service

build-extension: ## Build ig-service image to be deployed as a desktop extension
	docker build --tag=$(IMAGE):$(TAG) ..

prepare-buildx: ## Create buildx builder for multi-arch build, if not exists
	docker buildx inspect $(BUILDER) || docker buildx create --name=$(BUILDER) --driver=docker-container --driver-opt=network=host

push-extension: prepare-buildx ## Build & Upload extension image to hub. Do not push if tag already exists: make push-extension TAG=0.1
	docker buildx build --push --builder=$(BUILDER) -f Dockerfile --platform=linux/amd64,linux/arm64 --build-arg TAG=$(TAG) --tag=$(IMAGE):$(TAG) ..
	@echo "$(IMAGE):$(TAG)"


