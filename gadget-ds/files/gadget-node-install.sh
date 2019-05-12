#!/bin/bash

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a pod with access to the host via /host" >&2
  exit 1
fi

CGROUP_V1_PATH=$(cat /proc/1/cgroup |grep ^1:|cut -d: -f3)
CGROUP_V2_PATH=$(cat /proc/1/cgroup |grep ^0:|cut -d: -f3)

if [ $CGROUP_V1_PATH != $CGROUP_V2_PATH ] ; then
  echo "cgroup-v2 is not correctly enabled on Kubernetes pods" >&2
  exit 1
fi

HOOK_LOCK=/run/runc-hook-prestart.lock

: >> $HOOK_LOCK
{
set -e
flock -w 1 $HOOK_LOCK_FD || { echo "Cannot acquire lock" ; exit 1 ; }

export BPFTOOL=/bin/bpftool
/bin/runc-hook-prestart-create-maps.sh

mkdir -p /host/opt/bin/
for i in bpftool cgroupid kubectl runc-hook-prestart.sh runc-hook-prestart-create-maps.sh ; do 
  cp /bin/$i /host/opt/bin/
done

## runc is already patched on Flatcar Edge:
## https://github.com/flatcar-linux/coreos-overlay/pull/23/files
if ! grep -q /opt/bin/runc-hook-prestart.sh /run/torcx/unpack/docker/bin/runc ; then
  mount -o remount,rw /run/torcx/unpack
  if [ ! -e /run/torcx/unpack/docker/bin/runc.vanilla ] ; then
    cp /run/torcx/unpack/docker/bin/runc /run/torcx/unpack/docker/bin/runc.vanilla
  fi
  cp /bin/runc-static-hooks /run/torcx/unpack/docker/bin/runc
  mount -o remount,ro /run/torcx/unpack || true
fi
} {HOOK_LOCK_FD}<$HOOK_LOCK

echo -n OK
