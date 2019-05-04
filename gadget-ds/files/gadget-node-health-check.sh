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

for i in bpftool cgroupid kubectl runc-hook-prestart.sh ; do 
  if [ ! -x /host/opt/bin/$i ] ; then
    echo "$i is not installed correctly" >&2
    exit 1
  fi
done

if ! grep -q /opt/bin/runc-hook-prestart.sh /run/torcx/unpack/docker/bin/runc ; then
  echo "runc is not installed correctly: Inspektor Gadget requires https://github.com/kinvolk/runc/tree/alban/static-hooks" >&2
  exit 1
fi

echo -n OK
