#!/bin/sh

set -e
set -x

BPFTOOL=${BPFTOOL:-bpftool}

bpfdir=/sys/fs/bpf
innermap=$bpfdir/containermapinner

rm -f $innermap
rm -f $bpfdir/containermap

$BPFTOOL map create $innermap type hash key 64 value 64 entries 64 name containermapinner flags 1
$BPFTOOL map create $bpfdir/containermap type hash_of_maps innermap pinned $innermap key 64 value 4 entries 64 name containermap flags 1
