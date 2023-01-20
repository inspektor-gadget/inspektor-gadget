#!/bin/bash

kubectl delete ns demo || true
kubectl create ns demo
kubectl run -n demo --image busybox demo-pod-0 -- sleep inf
kubectl run -n demo --image busybox demo-pod-1 -- sleep inf
kubectl run -n demo --image busybox demo-pod-2 -- sleep inf

sleep 5
