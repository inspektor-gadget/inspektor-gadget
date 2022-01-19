#!/bin/bash

# Copyright 2019-2021 The Inspektor Gadget authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

MANAGER=true
PROBECLEANUP=false

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
    --containername)
        CONTAINERNAME="$2"
        shift
        shift
        ;;
    --tool-mode)
        TOOLMODE="$2"
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

if [ "$TOOLMODE" = "default" ] || [ -z "$TOOLMODE" ]; then
  TOOLMODE="$INSPEKTOR_GADGET_OPTION_DEFAULT_TOOL_MODE"
fi

if [ "$TOOLMODE" = "auto" ] ; then
  # kernel provided BTF
  if test -f /sys/kernel/btf/vmlinux; then
    TOOLMODE="core"
  # btfhub / btfgen provided BTF
  elif test -f /boot/vmlinux-$KERNEL; then
    TOOLMODE="core"
  else
    TOOLMODE="standard"
  fi
fi

if [ "$MANAGER" = "false" ] ; then
  GADGETPATH="$GADGET"
elif [ "$TOOLMODE" = "standard" ] ; then
  GADGETPATH="/usr/share/bcc/tools/$GADGET"
elif [ "$TOOLMODE" = "core" ]; then
  GADGETPATH="/bin/libbpf-tools/$GADGET"
else
  echo "Invalid value for tools-mode: $TOOLMODE"
  exit 1
fi

echo $$ > $PIDFILE

export TERM=xterm-256color
export PYTHONUNBUFFERED=TRUE

if [ "$MANAGER" = "true" ] ; then
  $GADGETTRACERMANAGER -call add-tracer -tracerid "$TRACERID" -label "$LABEL" -namespace "$NAMESPACE" -podname "$PODNAME" -containername "$CONTAINERNAME" > /dev/null
  # use the --cgroupmap option if the system is using cgroup-v2
  MODE="--mntnsmap"
  MAPPATH=$BPFDIR/gadget/mntnsset_$TRACERID
  CGROUP_V2_PATH=$(cat /proc/self/cgroup |grep ^0:|cut -d: -f3)
  UID_UNDER=`echo $GADGET_POD_UID | sed 's/-/_/g'`
  if [[ "$CGROUP_V2_PATH" == *"$GADGET_POD_UID"* ||
      "$CGROUP_V2_PATH" == *"$UID_UNDER"* ]]; then
    MODE="--cgroupmap"
    MAPPATH=$BPFDIR/gadget/cgroupidset_$TRACERID
  fi
  exec $GADGETPATH $MODE $MAPPATH "$@"
else
  exec $GADGETPATH "$@"
fi
