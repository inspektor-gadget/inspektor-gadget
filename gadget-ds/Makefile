.PHONY: build docker-bcc/build docker-bcc/push docker-gadget/build docker-gadget/push

IMAGE_TAG=$(shell ../tools/image-tag)

build: docker-bcc/build docker-gadget/build

push: docker-gadget/push

docker-bcc/build:
	docker build -t docker.io/kinvolk/bcc:latest -f bcc.Dockerfile .

docker-bcc/push:
	docker push docker.io/kinvolk/bcc:latest

docker-gadget/build:
	docker build -t docker.io/kinvolk/gadget:$(IMAGE_TAG) -f gadget.Dockerfile .

docker-gadget/push:
	docker push docker.io/kinvolk/gadget:$(IMAGE_TAG)
