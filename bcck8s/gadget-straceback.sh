#!/bin/bash

set -e

STRACEBACK_PODS=$(kubectl get pod -l name=straceback -o jsonpath='{range .items[*]}{.metadata.name}{" "}{end}')

case $1 in
list)
  for POD in $STRACEBACK_PODS ; do
    kubectl exec -ti $POD -- curl --unix-socket /run/straceback.socket "http://localhost/list" | strings | sed 's/[0-9]*: \[\(.*\)\] .*$/\1/'
  done
  ;;
show)
  for POD in $STRACEBACK_PODS ; do
    kubectl exec -ti $POD -- curl --unix-socket /run/straceback.socket "http://localhost/dump-by-name?name=$2"
  done
  ;;
close)
  for POD in $STRACEBACK_PODS ; do
    kubectl exec -ti $POD -- curl --unix-socket /run/straceback.socket "http://localhost/close-by-name?name=$2"
  done
  ;;
*)
  echo "usage:"
  echo "  $0 list"
  echo "  $0 show [id]"
  echo "  $0 close [id]"
esac
