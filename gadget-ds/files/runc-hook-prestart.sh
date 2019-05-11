#!/bin/bash

read JSON
PID=$(echo $JSON | jq -r '.pid')
ID=$(echo $JSON | jq -r '.id')
CONTAINERID_HEX=$(printf "%-64s" "$ID" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)

BPFTOOL=/opt/bin/bpftool
CGROUPID=/opt/bin/cgroupid
KUBECTL=/opt/bin/kubectl

HOOK_LOCK=/tmp/runc-hook-prestart.lock

BPFDIR=/sys/fs/bpf
CGROUP_PATH=/sys/fs/cgroup/unified$(cat /proc/$PID/cgroup|grep ^0::|cut -b4-)
CGROUP_ID=$($CGROUPID $CGROUP_PATH)
CGROUP_ID_HEX=$(printf '%016x' $CGROUP_ID | sed -re 's:([0-9A-Fa-f]{2}):\1\n:g' | tac | tr '\n' ' ')

exec >> /tmp/runc-hook-prestart-${CGROUP_ID}.log
exec 2>&1

echo CGROUP_PATH=$CGROUP_PATH
echo CGROUP_ID=$CGROUP_ID

PPPID=$(cat /proc/$PID/status | grep PPid|cut -f2)
BUNDLE_DIR=/run/docker/libcontainerd/containerd/io.containerd.runtime.v1.linux/moby/
BUNDLE_DIR="$(cat /proc/$PPPID/cmdline | tr '\0' '\n' | grep -A1 -- --bundle | tail -1)"
echo BUNDLE_DIR="$BUNDLE_DIR"
if cat $BUNDLE_DIR/config.json | jq -r .process.args[0] | grep -q /pause ; then
  PAUSE_CONTAINER=yes
else
  PAUSE_CONTAINER=no
fi

# Re-creating the maps is done in a shell mutex (using flock)
# Even Kubernetes pods with only one containers have a second container (the
# pause container) started at the same time. So two instances of this script
# are called in parallel.
: >> $HOOK_LOCK
{
flock $HOOK_LOCK_FD
if [ ! -f $BPFDIR/cgroupmap ] ; then
  $BPFTOOL map create $BPFDIR/cgroupmap type hash key 8 value 64 entries 8000 name cgroupmap flags 1
fi
if [ ! -f $BPFDIR/containermap -o ! -f $BPFDIR/cgrouplabelsmap -o ! -f $BPFDIR/cgroupmetadatas ] ; then
  INNERMAP=$BPFDIR/containermapinner
  INNERMAPMETA=$BPFDIR/containermapinnermeta
  rm -f $INNERMAP
  rm -f $INNERMAPMETA
  rm -f $BPFDIR/containermap
  rm -f $BPFDIR/cgrouplabelsmap
  rm -f $BPFDIR/cgroupmetadatas
  # templates for inner maps
  $BPFTOOL map create $INNERMAP type hash key 64 value 64 entries 64 name containermapinner flags 1
  $BPFTOOL map create $INNERMAPMETA type array key 4 value 64 entries 2 name containermapinnermeta
  # containermap is only needed in Flatcar alpha/beta/stable, not Edge where an OCI hook exists. It is written by pidmap and read by *snoop (not *snoop-edge)
  $BPFTOOL map create $BPFDIR/containermap type hash_of_maps innermap pinned $INNERMAP key 64 value 4 entries 8000 name containermap flags 1
  # create map from cgroup ID to label map, filled with maps for all pods here later, read by *snoop-edge (note: this name has max length for bpftool map show)
  $BPFTOOL map create $BPFDIR/cgrouplabelsmap type hash_of_maps innermap pinned $INNERMAP key 8 value 4 entries 8000 name cgrouplabelsmap flags 1
  # create map from cgroup ID to metadata map, filled with maps for all pods here later, read by *snoop-edge
  $BPFTOOL map create $BPFDIR/cgroupmetadatas type hash_of_maps innermap pinned $INNERMAPMETA key 8 value 4 entries 8000 name cgroupmetadatas flags 1
fi
} {HOOK_LOCK_FD}<$HOOK_LOCK

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
    # create label and metadata map for this pod
    rm -f $BPFDIR/labels$CGROUP_ID
    $BPFTOOL map create $BPFDIR/labels$CGROUP_ID type hash key 64 value 64 entries 64 name labels$CGROUP_ID flags 1
    rm -f $BPFDIR/metadata$CGROUP_ID
    $BPFTOOL map create $BPFDIR/metadata$CGROUP_ID type array key 4 value 64 entries 2 name metadata$CGROUP_ID

    if [ "$PAUSE_CONTAINER" = "no" ] ; then
      echo "Registering to straceback"
      curl --unix-socket /run/straceback.socket "http://localhost/add?name=${nodename}_${namespace}_${podname}&cgrouppath=${CGROUP_PATH}" || true
    else
      echo "Found pause container. Don't register to straceback"
    fi

    echo "Metadata"
    set -x
    # 0: namespace, 1: podname
    namespace_hex=$(printf "%-64s" "$namespace" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
    echo "  $namespace_hex"
    podname_hex=$(printf "%-64s" "$podname" | od -t x1 -w64 -v | head -1 | cut -d" " -f2-)
    echo "  $podname_hex"
    $BPFTOOL map update pinned $BPFDIR/metadata$CGROUP_ID key 0 0 0 0 value hex $namespace_hex
    echo "bpftool map updated returned: $?"
    $BPFTOOL map update pinned $BPFDIR/metadata$CGROUP_ID key 1 0 0 0 value hex $podname_hex
    echo "bpftool map updated returned: $?"
    # update cgroup ID map to point to this new pod map
    $BPFTOOL map update pinned $BPFDIR/cgroupmetadatas key hex $CGROUP_ID_HEX value pinned $BPFDIR/metadata$CGROUP_ID
    echo "bpftool map updated returned: $?"

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
