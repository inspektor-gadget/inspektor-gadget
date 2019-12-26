.PHONY: build docker-bcc/build docker-bcc/push docker-gadget/build docker-gadget/push

IMAGE_TAG=$(shell ../tools/image-tag)
IMAGE_BRANCH_TAG=$(shell ../tools/image-tag branch)

build: docker-bcc/build docker-gadget/build

push: docker-gadget/push

docker-bcc/build:
	docker build -t docker.io/kinvolk/bcc:ig-latest -f bcc.Dockerfile .

docker-bcc/push:
	docker push docker.io/kinvolk/bcc:ig-latest

docker-gadget/build:
	docker build -t docker.io/kinvolk/gadget:$(IMAGE_TAG) -f gadget.Dockerfile .
	docker tag docker.io/kinvolk/gadget:$(IMAGE_TAG) docker.io/kinvolk/gadget:$(IMAGE_BRANCH_TAG)

minikube: docker-gadget/minikube-build docker-gadget/minikube-install

docker-gadget/minikube-build:
	cp ../../traceloop/traceloop ./
	eval $(shell minikube docker-env | grep =) ; docker build --no-cache -t docker.io/kinvolk/gadget:minikube -f gadget-from-local-bin.Dockerfile .
	rm -f traceloop

docker-gadget/minikube-install:
	kubectl patch ds -n kube-system gadget -p $$'spec:\n template:\n  spec:\n   containers:\n    - name: gadget\n      image: docker.io/kinvolk/gadget:minikube\n      imagePullPolicy: Never'
	kubectl delete pod -n kube-system -l 'k8s-app=gadget'
	kubectl get pod -n kube-system -l 'k8s-app=gadget'

docker-gadget/push:
	docker push docker.io/kinvolk/gadget:$(IMAGE_TAG)
	docker push docker.io/kinvolk/gadget:$(IMAGE_BRANCH_TAG)
