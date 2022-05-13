#!/bin/bash

kubectl delete pod -n demo mypod --force
kubectl delete ns demo || true

