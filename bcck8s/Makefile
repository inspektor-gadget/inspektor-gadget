image:
	docker build -t albanc/bcck8s .

push:
	docker push albanc/bcck8s:latest

test:
	kubectl exec -ti bcc-shell-g87lr /bin/opensnoop.sh

install:
	for POD in $$(kubectl get pod -l name=bcck8s-shell -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}') ; do \
		kubectl cp ./opensnoop-edge $$POD:/opensnoop-edge ; \
		kubectl cp ./execsnoop-edge $$POD:/execsnoop-edge ; \
		kubectl cp ./tcptop-edge $$POD:/tcptop-edge ; \
	done

