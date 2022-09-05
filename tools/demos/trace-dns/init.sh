#!/bin/bash

kubectl delete ns demo || true
kubectl create ns demo

# Make sure the busybox image is downloaded
kubectl run --rm -ti --restart=Never -n demo loader --image busybox -- sh -c 'echo OK'
