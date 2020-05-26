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

echo -n "bcc detected: "
dpkg-query --show libbcc|awk '{print $2}'

echo -n "Gadget image: "
echo $TRACELOOP_IMAGE

echo "Deployment options:"
env | grep '^INSPEKTOR_GADGET_OPTION_.*='

echo -n "Inspektor Gadget version: "
echo $INSPEKTOR_GADGET_VERSION

# gobpf currently uses global kprobes via debugfs/tracefs and not the Perf
# Event file descriptor based kprobe (Linux >=4.17). So unfortunately, kprobes
# can remain from previous executions. Ideally, gobpf should implement Perf
# Event based kprobe and fallback to debugfs/tracefs, like bcc:
# https://github.com/iovisor/bcc/blob/6e9b4509fc7a063302b574520bac6d49b01ca97e/src/cc/libbpf.c#L1021-L1027
# Meanwhile, as a workaround, delete probes manually.
# See: https://github.com/iovisor/gobpf/issues/223
echo "-:pfree_uts_ns" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
echo "-:pcap_capable" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true

ARGS=k8s
FLATCAR_EDGE=0
if grep -q '^ID=flatcar$' /host/etc/os-release > /dev/null ; then
  if grep -q '^GROUP=edge$' /host/etc/flatcar/update.conf > /dev/null ; then
    echo "Flatcar Edge detected."
    FLATCAR_EDGE=1

    CGROUP_V1_PATH=$(cat /proc/1/cgroup |grep ^1:|cut -d: -f3)
    CGROUP_V2_PATH=$(cat /proc/1/cgroup |grep ^0:|cut -d: -f3)
    if [ $CGROUP_V1_PATH != $CGROUP_V2_PATH ] ; then
      echo "cgroup-v2 is not correctly enabled on Kubernetes pods" >&2
      exit 1
    fi
  fi
fi

# Choose what runc hook mode to use based on the configuration detected
RUNC_HOOK_MODE="$INSPEKTOR_GADGET_OPTION_RUNC_HOOKS_MODE"

if [ "$RUNC_HOOK_MODE" = "auto" ] ; then
  if [ "$FLATCAR_EDGE" = 1 ] ; then
    echo "runc hook mode flatcar_edge detected."
    RUNC_HOOK_MODE="flatcar_edge"
  else
    RUNC_HOOK_MODE="error"
    echo "Error detecting runc hook mode."
  fi
fi

if [ "$RUNC_HOOK_MODE" = "ldpreload" ] ; then
  echo "Installing ld.so.preload with runchooks.so for OCI hooks"
  mkdir -p /host/opt/runchooks/
  cp /opt/runchooks/runchooks.so /host/opt/runchooks/
  cp /opt/runchooks/add-hooks.jq /host/opt/runchooks/
  touch /host/etc/ld.so.preload
  if grep -q ^/opt/runchooks/runchooks.so$ /host/etc/ld.so.preload > /dev/null ; then
    echo "runchooks.so already setup in /etc/ld.so.preload"
  else
    echo "/opt/runchooks/runchooks.so" >> /host/etc/ld.so.preload
  fi
fi

if [ "$RUNC_HOOK_MODE" = "flatcar_edge" ] ||
   [ "$RUNC_HOOK_MODE" = "ldpreload" ] ; then
  echo "Installing hooks scripts on host..."

  mkdir -p /host/opt/bin/
  for i in ocihookgadget runc-hook-prestart.sh runc-hook-poststop.sh ; do
    echo "Installing $i..."
    cp /bin/$i /host/opt/bin/
  done
  echo "Installation done"
fi

echo "Starting the Gadget Tracer Manager in the background..."
rm -f /run/gadgettracermanager.socket
/bin/gadgettracermanager -serve &

if [ "$INSPEKTOR_GADGET_OPTION_TRACELOOP" = "true" ] ; then
  rm -f /run/traceloop.socket
  exec /bin/traceloop $ARGS
fi

echo "Ready."
sleep infinity
