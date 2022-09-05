#!/bin/bash

kubectl gadget undeploy || true
kubectl delete ns demo || true
