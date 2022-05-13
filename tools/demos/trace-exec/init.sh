#!/bin/bash

kubectl delete ns demo || true
kubectl create ns demo

kubectl run -n demo --restart=Never --image=busybox mypod -- sh -c 'while true; do /bin/ls ; /bin/sleep 1 ; done' 
kubectl wait --timeout=30s -n demo --for=condition=ready pod/mypod
