#!/bin/bash

kubectl delete pod -n demo mypod
kubectl delete ns demo || true

