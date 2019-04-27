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

install-hooks:
	scp ./runc-hook-prestart.sh realedge-w1:/tmp/runc-hook-prestart.sh
	scp ./runc-hook-prestart.sh realedge-w2:/tmp/runc-hook-prestart.sh
	ssh realedge-w1 sudo mv /tmp/runc-hook-prestart.sh /opt/bin/runc-hook-prestart.sh
	ssh realedge-w2 sudo mv /tmp/runc-hook-prestart.sh /opt/bin/runc-hook-prestart.sh

