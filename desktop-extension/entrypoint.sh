#!/bin/sh

set -e

if [ ! -r /host/etc/os-release ] ; then
  echo "$0 must be executed in a container with access to the host via /host" >&2
  exit 1
fi

. /host/etc/os-release

echo -n "OS detected: "
echo $PRETTY_NAME

KERNEL=$(uname -r)
echo -n "Kernel detected: "
echo $KERNEL

if ! readlink /host/proc/self > /dev/null ; then
  echo "/host/proc's pidns is neither the current pidns or a parent of the current pidns. Remounting."
  mount --bind /proc /host/proc
fi

BPF_MOUNTPOINT_TYPE="`stat -f -c %T /sys/fs/bpf`"
if [ "$BPF_MOUNTPOINT_TYPE" != "bpf_fs" ] ; then
  echo "/sys/fs/bpf is of type $BPF_MOUNTPOINT_TYPE. Remounting."
  mount -t bpf bpf /sys/fs/bpf/
fi

DEBUG_MOUNTPOINT_TYPE="`stat -f -c %T /sys/kernel/debug`"
if [ "$DEBUG_MOUNTPOINT_TYPE" != "debugfs" ] ; then
  echo "/sys/kernel/debug is of type $DEBUG_MOUNTPOINT_TYPE. Remounting."
  mount -t debugfs debugfs /sys/kernel/debug
fi

TRACE_MOUNTPOINT_TYPE="`stat -f -c %T /sys/kernel/tracing`"
if [ "$TRACE_MOUNTPOINT_TYPE" != "tracefs" ] ; then
  echo "/sys/kernel/tracing is of type $TRACE_MOUNTPOINT_TYPE. Remounting."
  mount -t tracefs tracefs /sys/kernel/tracing
fi

echo "Creating directory for $IG_DESKTOP_EXTENSION_SOCKET..."
IG_DESKTOP_EXTENSION_SOCKET_DIR=$(dirname $IG_DESKTOP_EXTENSION_SOCKET)
mkdir -p $IG_DESKTOP_EXTENSION_SOCKET_DIR

echo "Starting ig-service..."
exec /bin/ig-service -socket $IG_DESKTOP_EXTENSION_SOCKET
