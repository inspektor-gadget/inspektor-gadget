#!/bin/bash

set -e

CONTAINERINDEX=-1
MANAGER=true
PROBECLEANUP=false
FLATCAREDGEONLY=false

while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    --tracerid)
        TRACERID="$2"
        shift
        shift
        ;;
    --stop)
        STOP=true
        shift
        ;;
    --flatcaredgeonly)
        FLATCAREDGEONLY=true
        shift
        ;;
    --nomanager)
        MANAGER=false
        shift
        ;;
    --probecleanup)
        PROBECLEANUP=true
        shift
        ;;
    --gadget)
        GADGET="$2"
        shift
        shift
        ;;
    --label)
        LABEL="$2"
        shift
        shift
        ;;
    --namespace)
        NAMESPACE="$2"
        shift
        shift
        ;;
    --podname)
        PODNAME="$2"
        shift
        shift
        ;;
    --containerindex)
        CONTAINERINDEX="$2"
        shift
        shift
        ;;
    --)
        shift
        break
        ;;
    *)
        echo "Unknown key: $key" >&2
        exit 1
        ;;
esac
done

GADGETTRACERMANAGER=/bin/gadgettracermanager
BPFDIR="${BPFDIR:-/sys/fs/bpf}"

if [ "$FLATCAREDGEONLY" = "true" ] ; then
  if ! grep -q '^ID=flatcar$' /host/etc/os-release > /dev/null ; then
    echo "Gadget not available." >&2
    exit 1
  fi
  if ! grep -q '^GROUP=edge$' /host/etc/flatcar/update.conf > /dev/null ; then
    echo "Gadget not available." >&2
    exit 1
  fi
fi

PIDFILE=/run/bcc-wrapper-$TRACERID.pid

if [ "$STOP" = "true" ] ; then
  if [ "$MANAGER" = "true" ] ; then
    $GADGETTRACERMANAGER -call remove-tracer -tracerid "$TRACERID" || true
  fi
  if [ -e "$PIDFILE" ] ; then
    kill -SIGINT "$(cat $PIDFILE)" || true
    timeout 5s tail --pid="$(cat $PIDFILE)" -f /dev/null
    kill -9 "$(cat $PIDFILE)" || true
    rm -f "$PIDFILE"
  fi
  exit 0
fi

if [ "$PROBECLEANUP" = "true" ] ; then
  if [ -e "$PIDFILE" ] ; then
    kill -9 "$(cat $PIDFILE)" 2>/dev/null || true
    rm -f "$PIDFILE"
    sleep 0.5
  fi

  # gobpf currently uses global kprobes via debugfs/tracefs and not the Perf
  # Event file descriptor based kprobe (Linux >=4.17). So unfortunately, kprobes
  # can remain from previous executions. Ideally, gobpf should implement Perf
  # Event based kprobe and fallback to debugfs/tracefs, like bcc:
  # https://github.com/iovisor/bcc/blob/6e9b4509fc7a063302b574520bac6d49b01ca97e/src/cc/libbpf.c#L1021-L1027
  # Meanwhile, as a workaround, delete probes manually.
  # See: https://github.com/iovisor/gobpf/issues/223
  echo "-:ptcp_set_state" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:ptcp_v4_connect" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:rtcp_v4_connect" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:ptcp_v6_connect" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:rtcp_v6_connect" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:rinet_csk_accept" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:ptcp_close" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:pfd_install" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
  echo "-:rfd_install" >> /sys/kernel/debug/tracing/kprobe_events 2>/dev/null || true
fi

echo $$ > $PIDFILE

export TERM=xterm-256color
export PYTHONUNBUFFERED=TRUE

if [ "$MANAGER" = "true" ] ; then
  $GADGETTRACERMANAGER -call add-tracer -tracerid "$TRACERID" -label "$LABEL" -namespace "$NAMESPACE" -podname "$PODNAME" -containerindex "$CONTAINERINDEX" > /dev/null
  # use the --cgroupmap option if the system is using cgroup-v2
  MODE="--mntnsmap"
  MAPPATH=$BPFDIR/gadget/mntnsset-$TRACERID
  CGROUP_V2_PATH=$(cat /proc/self/cgroup |grep ^0:|cut -d: -f3)
  if [ ! -z "$CGROUP_V2_PATH" ] && [ "$CGROUP_V2_PATH" != "/" ]; then
    MODE="--cgroupmap"
    MAPPATH=$BPFDIR/gadget/cgroupidset-$TRACERID
  fi
  exec $GADGET $MODE $MAPPATH "$@"
else
  exec $GADGET "$@"
fi
