#!/bin/bash

# Re-creating the maps is done in a shell mutex (using flock)
# Even Kubernetes pods with only one containers have a second container (the
# pause container) started at the same time. So two instances of this script
# are called in parallel.

BPFTOOL="${BPFTOOL:-/opt/bin/bpftool}"
BPFDIR="${BPFDIR:-/sys/fs/bpf}"

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
  find $BPFDIR/ -name 'labels[0-9]*' -delete
  find $BPFDIR/ -name 'metadata[0-9]*' -delete

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
