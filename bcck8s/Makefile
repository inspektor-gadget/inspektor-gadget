POD ?= bcc-shell-g87lr

image:
	docker build -t albanc/bcck8s .

push:
	docker push albanc/bcck8s:latest

test:
	kubectl exec -ti bcc-shell-g87lr /bin/opensnoop.sh

install:
	kubectl cp ./opensnoop $(POD):/bin/opensnoop
	kubectl cp ./opensnoop.sh $(POD):/bin/opensnoop.sh
	kubectl cp ./bpftool $(POD):/bin/bpftool

