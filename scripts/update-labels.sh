#!/bin/bash

set -e

bpfdir=/sys/fs/bpf/containerids
sudo mkdir -p $bpfdir

kubectl get pod --all-namespaces -o json | \
  jq -r '.items[] |
	{
		namespace: .metadata.namespace,
		podName: .metadata.name,
		nodename: .status.hostIP,
		labels: .metadata.labels | @base64,
		statuses: .status.containerStatuses[] |
			{
				containerId: .containerID | sub("^docker://"; ""),
				containerName: .name
			}
	} |
	[.namespace, .podName, .nodename, .labels, .statuses.containerId, .statuses.containerName] |
	@tsv' | \
  while IFS=$'\t' read -r namespace podname nodename labels containerid containername; do
    echo $containerid
    sudo rm -f $bpfdir/$containerid
    sudo bpftool map create $bpfdir/$containerid type hash key 64 value 64 entries 64 name $containerid flags 1
    echo $labels | base64 -d | \
	jq -r 'to_entries[] |
		{
			key: .key,
			value: .value
		} |
		[.key, .value] |
		@tsv' | \
	while IFS=$'\t' read -r key value; do
		echo "add $key=$value in $containerid"
		key_hex=$(printf "%-64s" "$key" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
		value_hex=$(printf "%-64s" "$value" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
		sudo bpftool map update pinned $bpfdir/$containerid key hex $key_hex value hex $value_hex
	done
	containerid_hex=$(echo -n "$containerid" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
	sudo bpftool map update pinned /sys/fs/bpf/containermap key hex $containerid_hex value pinned $bpfdir/$containerid
  done
