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
  exec $GADGET $MODE $MAPPATH "$@"
else
  exec $GADGET "$@"
fi
