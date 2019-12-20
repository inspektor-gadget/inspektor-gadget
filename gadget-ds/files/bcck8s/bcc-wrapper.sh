#!/bin/bash

set -e

CONTAINERINDEX=-1

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

if ! grep -q '^ID=flatcar$' /host/etc/os-release > /dev/null ; then
  echo "Gadget not available." >&2
  exit 1
fi

if ! grep -q '^GROUP=edge$' /host/etc/flatcar/update.conf > /dev/null ; then
  echo "Gadget not available." >&2
  exit 1
fi

PIDFILE=/run/bcc-wrapper-$TRACERID.pid

if [ "$STOP" = "true" ] ; then
  $GADGETTRACERMANAGER -call remove-tracer -tracerid "$TRACERID"
  if [ -e "$PIDFILE" ] ; then
    kill -9 "$(cat $PIDFILE)" || true
    rm -f "$PIDFILE"
  fi
  exit 0
fi

echo $$ > $PIDFILE

$GADGETTRACERMANAGER -call add-tracer -tracerid "$TRACERID" -label "$LABEL" -namespace "$NAMESPACE" -podname "$PODNAME" -containerindex "$CONTAINERINDEX" > /dev/null
CGROUPMAP=$BPFDIR/gadget/cgroupidset-$TRACERID

export TERM=xterm-256color

exec /opt/bcck8s/$GADGET --cgroupmap $CGROUPMAP "$@"
