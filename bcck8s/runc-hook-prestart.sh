#!/bin/sh

read JSON
PID=$(echo $JSON | jq -r '.pid')
ID=$(echo $JSON | jq -r '.id')
CONTAINERID_HEX=$(printf "%-64s" "$ID" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)

BPFTOOL=/opt/bin/bpftool
CGROUPID=/opt/bin/cgroupid
KUBECTL=/opt/bin/kubectl

BPFDIR=/sys/fs/bpf
CGROUP_PATH=/sys/fs/cgroup/unified$(cat /proc/$PID/cgroup|grep ^0::|cut -b4-)
CGROUP_ID=$($CGROUPID $CGROUP_PATH)
CGROUP_ID_HEX=$(printf '%016x' $CGROUP_ID | sed -re 's:([0-9A-Fa-f]{2}):\1 :g')

exec >> /tmp/runc-hook-prestart-${CGROUP_ID}.log
exec 2>&1

echo CGROUP_PATH=$CGROUP_PATH
echo CGROUP_ID=$CGROUP_ID

if [ ! -f $BPFDIR/cgroupmap ] ; then
  $BPFTOOL map create $BPFDIR/cgroupmap type hash key 8 value 64 entries 8000 name cgroupmap flags 1
fi
if [ ! -f $BPFDIR/cgrouplabelsmap ] ; then
  INNERMAP=$BPFDIR/containermapinner
  rm -f $INNERMAP
  rm -f $BPFDIR/containermap
  rm -f $BPFDIR/cgrouplabelsmap
  $BPFTOOL map create $INNERMAP type hash key 64 value 64 entries 64 name containermapinner flags 1
  $BPFTOOL map create $BPFDIR/containermap type hash_of_maps innermap pinned $INNERMAP key 64 value 4 entries 8000 name containermap flags 1
  $BPFTOOL map create $BPFDIR/cgrouplabelsmap type hash_of_maps innermap pinned $INNERMAP key 8 value 4 entries 8000 name containermap flags 1
fi

$BPFTOOL map update pinned $BPFDIR/cgroupmap key hex $CGROUP_ID_HEX value hex $CONTAINERID_HEX

$KUBECTL --kubeconfig=/etc/kubernetes/kubeconfig get pod --all-namespaces -o json | tee /tmp/kubectl-get-pods-${CGROUP_ID}.json | \
  jq -r '.items[] |
	{
		uid: .metadata.uid,
		namespace: .metadata.namespace,
		podName: .metadata.name,
		nodename: .status.hostIP,
		labels: .metadata.labels | @base64,
		statuses: .status.containerStatuses[] |
			{
				containerId: .containerID,
				containerName: .name
			}
	} |
	[.uid, .namespace, .podName, .nodename, .labels, .statuses.containerId, .statuses.containerName] |
	@tsv' | \
  while IFS=$'\t' read -r uid namespace podname nodename labels containername; do
    set -e
    if ! grep -q "${uid//-/_}" <<<"$CGROUP_PATH" ; then
      continue
    fi
    echo "Processing container: $namespace $podname $nodename $containername"
    rm -f $BPFDIR/labels$CGROUP_ID
    $BPFTOOL map create $BPFDIR/labels$CGROUP_ID type hash key 64 value 64 entries 64 name labels$CGROUP_ID flags 1
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
	while IFS=$'\t' read -r key value; do
                set -e
		echo "Processing label $key=$value in $CGROUP_ID"
		key_hex=$(printf "%-64s" "$key" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
		value_hex=$(printf "%-64s" "$value" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
                echo "  $key_hex"
                echo "  $value_hex"
		$BPFTOOL map update pinned $BPFDIR/labels$CGROUP_ID key hex $key_hex value hex $value_hex
		echo "bpftool map updated returned: $?"
	done
	echo "Processing container $CGROUP_ID"
	$BPFTOOL map update pinned $BPFDIR/cgrouplabelsmap key hex $CGROUP_ID_HEX value pinned $BPFDIR/labels$CGROUP_ID
	echo "bpftool map updated returned: $?"
  done

echo done.
