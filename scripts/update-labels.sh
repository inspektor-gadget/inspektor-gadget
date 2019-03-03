#!/bin/sh

set -e

bpfdir=/sys/fs/bpf/containerids
mkdir -p $bpfdir

kubectl get pod --all-namespaces -o json | \
  tee /tmp/allpods-1.log | \
  jq -r '.items[] |
	{
		namespace: .metadata.namespace,
		podName: .metadata.name,
		nodename: .status.hostIP,
		labels: .metadata.labels | @base64,
		statuses: .status.containerStatuses[] |
			select(.containerID != null) |
			{
				containerId: .containerID | sub("^docker://"; ""),
				containerName: .name
			}
	} |
	[.namespace, .podName, .nodename, .labels, .statuses.containerId, .statuses.containerName] |
	@tsv' | \
  tee /tmp/allpods-2.log | \
  while IFS=$'\t' read -r namespace podname nodename labels containerid containername; do
    set -e
    echo "Processing container: $namespace $podname $nodename $containerid $containername"
    rm -f $bpfdir/$containerid
    bpftool map create $bpfdir/$containerid type hash key 64 value 64 entries 64 name $containerid flags 1
    echo "Labels"
    echo $labels | base64 -d | jq '.'
    echo $labels | base64 -d | \
	jq -r 'to_entries[] |
		{
			key: .key,
			value: .value
		} |
		[.key, .value] |
		@tsv' | \
        tee /tmp/container-$containerid.log | \
	while IFS=$'\t' read -r key value; do
                set -e
		echo "Processing label $key=$value in $containerid"
		key_hex=$(printf "%-64s" "$key" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
		value_hex=$(printf "%-64s" "$value" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
		bpftool map update pinned $bpfdir/$containerid key hex $key_hex value hex $value_hex
	done
	containerid_hex=$(echo -n "$containerid" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
	bpftool map update pinned /sys/fs/bpf/containermap key hex $containerid_hex value pinned $bpfdir/$containerid
  done

set -x
grep -H . /tmp/allpods-*.log
grep -H . /tmp/container-*.log || true
