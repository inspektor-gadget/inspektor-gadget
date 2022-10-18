#!/bin/bash

kubectl delete pod -n demo test-pod
kubectl delete ns demo || true

