.PHONY: update
update:
	for GADGET in `kubectl get pod -n kube-system -l'k8s-app=gadget' --no-headers | awk '{print $$1}'` ; do \
		echo "Updating tracepkt on $$GADGET ..." ; \
		kubectl cp -n kube-system ./tracepkt.py $$GADGET:/opt/tracepkt/ ; \
		kubectl cp -n kube-system ./tracepkt.c $$GADGET:/opt/tracepkt/ ; \
	done

