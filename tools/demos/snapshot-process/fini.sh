#!/bin/bash

source $(dirname ${BASH_SOURCE})/../util.sh

kubectl delete ns demo || true
