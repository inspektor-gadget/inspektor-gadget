#!/bin/bash

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a pod with access to the host via /host" >&2
  exit 1
fi

echo -n "OS detected: "
grep PRETTY_NAME= /host/etc/os-release|cut -d= -f2-

echo -n "Kernel detected: "
uname -r

echo -n "Gadget image: "
echo $TRACELOOP_IMAGE

echo -n "Inspektor Gadget version: "
echo $INSPEKTOR_GADGET_VERSION

ARGS=k8s
FLATCAR_EDGE=0
if grep -q '^ID=flatcar$' /host/etc/os-release > /dev/null ; then
  if grep -q '^GROUP=edge$' /host/etc/flatcar/update.conf > /dev/null ; then
    FLATCAR_EDGE=1
  fi
fi

if [ "$FLATCAR_EDGE" = 1 ] ; then
  echo "Flatcar Edge detected."
  echo "Installing scripts on host..."

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

  echo "Creating BPF maps..."
  export BPFTOOL=/bin/bpftool
  /bin/runc-hook-prestart-create-maps.sh

  mkdir -p /host/opt/bin/
  for i in bpftool cgroupid kubectl runc-hook-prestart.sh runc-hook-prestart-create-maps.sh ; do
    echo "Installing $i..."
    cp /bin/$i /host/opt/bin/
  done
  echo "Installation done "
  } {HOOK_LOCK_FD}<$HOOK_LOCK

fi

echo
rm -f /run/traceloop.socket
exec /bin/traceloop $ARGS
