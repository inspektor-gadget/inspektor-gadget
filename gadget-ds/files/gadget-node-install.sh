#!/bin/bash

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a pod with access to the host via /host" >&2
  exit 1
fi

if ! grep Flatcar /host/etc/os-release > /dev/null ; then
  echo "Only works on Flatcar Linux Edge or similar" >&2
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

} {HOOK_LOCK_FD}<$HOOK_LOCK

echo -n OK
