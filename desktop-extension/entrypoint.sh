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

# busybox's "stat -f -c %T" does not know all those filesystems
# So we have to use %t (hexadecimal codes)
FS_TYPE_BPF=cafe4a11
FS_TYPE_DEBUGFS=64626720
FS_TYPE_TRACEFS=74726163

BPF_MOUNTPOINT_TYPE="`stat -f -c %t /sys/fs/bpf`"
if [ "$BPF_MOUNTPOINT_TYPE" != "$FS_TYPE_BPF" ] ; then
  echo "/sys/fs/bpf is of type $BPF_MOUNTPOINT_TYPE. Remounting."
  mount -t bpf bpf /sys/fs/bpf/
fi

DEBUG_MOUNTPOINT_TYPE="`stat -f -c %t /sys/kernel/debug`"
if [ "$DEBUG_MOUNTPOINT_TYPE" != "$FS_TYPE_DEBUGFS" ] ; then
  echo "/sys/kernel/debug is of type $DEBUG_MOUNTPOINT_TYPE. Remounting."
  mount -t debugfs debugfs /sys/kernel/debug
fi

TRACE_MOUNTPOINT_TYPE="`stat -f -c %t /sys/kernel/tracing`"
if [ "$TRACE_MOUNTPOINT_TYPE" != "$FS_TYPE_TRACEFS" ] ; then
  echo "/sys/kernel/tracing is of type $TRACE_MOUNTPOINT_TYPE. Remounting."
  mount -t tracefs tracefs /sys/kernel/tracing
fi

echo "Creating directory for $IG_DESKTOP_EXTENSION_SOCKET..."
IG_DESKTOP_EXTENSION_SOCKET_DIR=$(dirname $IG_DESKTOP_EXTENSION_SOCKET)
mkdir -p $IG_DESKTOP_EXTENSION_SOCKET_DIR

export LIFECYCLE_SERVER_ROOT="/proc/$(pidof -s lifecycle-server)/root/"
if [ -f "$LIFECYCLE_SERVER_ROOT/usr/bin/runc" ] ; then
  echo "runc found in lifecycle-server's root. Switching HOST_ROOT."
  echo "export HOST_ROOT=\"$LIFECYCLE_SERVER_ROOT\""
  export HOST_ROOT="$LIFECYCLE_SERVER_ROOT"
fi

echo "Starting ig-service..."
exec /bin/ig-service -socket $IG_DESKTOP_EXTENSION_SOCKET
