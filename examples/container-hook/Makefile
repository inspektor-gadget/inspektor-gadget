CONTAINER_REPO ?= ghcr.io/inspektor-gadget/inspektor-gadget
IMAGE_TAG ?= $(shell ../../tools/image-tag branch)

container-hook: main.go
	CGO_ENABLED=0 go build -o container-hook main.go

container-hook-static: main.go
	CGO_ENABLED=0 go build -o container-hook-static -ldflags '-w -extldflags "-static"' main.go

# Example how container-hook can be used to show a stream of events
test-output:
	sudo ./container-hook -output "add,remove,config"

# Example how container-hook can be used to execute a prestart hook
test-hook:
	sudo ./container-hook -prestart 'cat > /tmp/hooks.log'

build-container:
	DOCKER_BUILDKIT=1 docker build -t $(CONTAINER_REPO)-container-hook:$(IMAGE_TAG) -f Dockerfile ../..

install:
	sed "s|image: .*:latest|image: $(CONTAINER_REPO)-container-hook:$(IMAGE_TAG)|" deploy.yaml | kubectl apply -f -

uninstall:
	kubectl delete -f deploy.yaml

clean:
	rm -f container-hook container-hook-static
