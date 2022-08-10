#! /usr/bin/env bash

registry='francisregistry.azurecr.io'
image_tag='francis-test-scaling'
container_repo="${registry}/gadget"

function prepare {
	IMAGE_TAG=${image_tag} CONTAINER_REPO=$container_repo make -C .. gadget-default-container
	IMAGE_TAG=${image_tag} CONTAINER_REPO=$container_repo make -C .. push-gadget-container
}

function prepare_csv_file {
	local csv_file=$1
	local nodes_nr=$2

	echo -n "" > $csv_file

	# Create CSV header
	for i in $(seq 1 ${nodes_nr}); do
		echo -n "node-${i}," >> $csv_file
	done
	echo "gadget" >> $csv_file
}

function pre_run {
	local namespace=$1

	kubectl create ns $namespace
	../kubectl-gadget deploy --image="${container_repo}:${image_tag}"
}

function run {
	local nodes_nr=$1
	local iter=$2
	local namespace=$3
	local gadget_dir=$4
	local csv_file=$5

	gadget_file="${gadget_dir}/gadget-output-${nodes_nr}-${iter}.out"
	../kubectl-gadget trace exec -n $namespace -o json > $gadget_file &
	gadget_pid=$!

	kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: daemonset-${nodes_nr}
  namespace: $namespace
spec:
  selector:
    matchLabels:
      k8s-app: stress-exec
  template:
    metadata:
      labels:
        k8s-app: stress-exec
    spec:
      securityContext:
        runAsUser: 1000
        runAsNonRoot: true
      initContainers:
      - name: stress-exec
        image: ghcr.io/colinianking/stress-ng:master
        workingDir: /tmp
        command: ["/bin/sh"]
        args: ["-c", "stress-ng --exec $(nproc) --exec-fork-method clone --exec-method execve --exec-no-pthread --timeout 1s --metrics-brief"]
      containers:
      - name: do-nothing
        image: alpine:latest
        command: ["sleep", "inf"]
EOF
	kubectl wait --for condition=Ready pods --all -n $namespace --timeout 120s

	# With the above wait, we will be sure all the pods will be ready.
	# But we actually do the real stress test in init container.
	# So, we can stop Inspektor Gadget once all the "real" pods are ready.
	kill $gadget_pid

	for pod in $(kubectl get pod -n $namespace --no-headers -o custom-columns=':metadata.name'); do
		# stress-ng output is like this:
		# stress-ng: info:  [1] setting to a 1 second run per stressor
		# stress-ng: info:  [1] dispatching hogs: 8 exec
		# stress-ng: info:  [1] stressor       bogo ops real time  usr time  sys time   bogo ops/s     bogo ops/s
		# stress-ng: info:  [1]                           (secs)    (secs)    (secs)   (real time) (usr+sys time)
		# stress-ng: info:  [1] exec               9157      1.00      4.44      1.51      9151.35        1538.99
		# stress-ng: info:  [1] successful run completed in 1.00s
		# We want to bogo ops, so they are in the 5th column and the only element to
		# be a number in this column.
		# We also need to specify the container with -c to get the logs of the init
		# container "stress-exec".
		nr_exec=$(kubectl logs -n $namespace $pod -c stress-exec | awk '{ print $5 }' | grep -P '\d+')
		echo -n "${nr_exec}," >> $csv_file
	done

	wc -l $gadget_file | awk '{ print $1 }' >> $csv_file
}

function post_run {
	local namespace=$1

	kubectl delete ns $namespace
	../kubectl-gadget undeploy
}

prepare

for nodes_nr in 2 5 11 17 23 31 39; do
	namespace="test-scaling-${nodes_nr}-nodes"
	gadget_dir="gadget-output-${nodes_nr}"
	csv_file="exec-${nodes_nr}-nodes.csv"

	az aks scale --resource-group francisrg --name franciscluster --node-count $nodes_nr --nodepool-name nodepool1

	mkdir $gadget_dir
	prepare_csv_file $csv_file $nodes_nr

	# Run the experiment.
	for exp in {1..30}; do
		pre_run $namespace
		run $nodes_nr $exp $namespace $gadget_dir $csv_file
		post_run $namespace
	done
done