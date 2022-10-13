CONTAINER_REPO ?= ghcr.io/inspektor-gadget/inspektor-gadget
IMAGE_TAG ?= $(shell ../../tools/image-tag branch)

runc-hook: main.go
	go build -o runc-hook main.go

runc-hook-static: main.go
	go build -o runc-hook-static -ldflags '-w -extldflags "-static"' main.go

# Example how runc-hook can be used to show a stream of events
test-output:
	sudo ./runc-hook -output "add,remove,config"

# Example how runc-hook can be used to execute a prestart hook
test-hook:
	sudo ./runc-hook -prestart 'cat > /tmp/hooks.log'

build-container:
	DOCKER_BUILDKIT=1 docker build -t $(CONTAINER_REPO)-runc-hook:$(IMAGE_TAG) -f Dockerfile ../..

install:
	sed "s|image: .*:latest|image: $(CONTAINER_REPO)-runc-hook:$(IMAGE_TAG)|" deploy.yaml | kubectl apply -f -

uninstall:
	kubectl delete -f deploy.yaml

clean:
	rm -f runc-hook runc-hook-static
