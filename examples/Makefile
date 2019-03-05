POD ?= bcc-shell-g87lr

test:
	kubectl exec -ti bcc-shell-g87lr /bin/opensnoop.sh

install:
	kubectl cp ./opensnoop $(POD):/bin/opensnoop
	kubectl cp ./opensnoop.sh $(POD):/bin/opensnoop.sh
	kubectl cp ./bpftool $(POD):/bin/bpftool

