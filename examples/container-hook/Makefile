CONTAINER_REPO ?= ghcr.io/inspektor-gadget/inspektor-gadget
IMAGE_TAG ?= $(shell ../../tools/image-tag branch)

container-hook: main.go
	go build -o container-hook main.go

container-hook-static: main.go
	go build -o container-hook-static -ldflags '-w -extldflags "-static"' main.go

# Example how container-hook can be used to show a stream of events
test-output:
	sudo ./container-hook -output "add,remove,config"

# Example how container-hook can be used to execute a prestart hook
test-hook:
	sudo ./container-hook -prestart 'cat > /tmp/hooks.log'

clean:
	rm -f container-hook container-hook-static
