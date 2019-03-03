#!/bin/sh

set -e
set -x

BPFTOOL=${BPFTOOL:-bpftool}

bpfdir=/sys/fs/bpf

innermap=/sys/fs/bpf/containerids/065001d1cd080f5559f455779fdb85e52d6f5c197fe83bac763c7bd1f08f4f6b

$BPFTOOL map create $bpfdir/containermap type hash_of_maps innermap pinned $innermap key 64 value 4 entries 64 name containermap flags 1
