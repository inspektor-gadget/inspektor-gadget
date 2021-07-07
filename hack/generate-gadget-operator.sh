#!/bin/bash
set -e
set -x

# Go to the root directory of inspektor-gadget
cd "$( dirname "${BASH_SOURCE[0]}" )"/..

# Tested with operator-sdk v1.9.0
operator-sdk version

# Generate sources in the gadget-operator directory
mkdir gadget-operator
cd gadget-operator
operator-sdk init --domain kinvolk.io --repo github.com/kinvolk/inspektor-gadget
operator-sdk create api --group gadget --version v1alpha1 --kind Trace --resource --controller
make manifests

echo "Differences between newly generated files"
diff -ur api ../pkg/api
diff -ur controllers ../pkg/controllers
diff -ur config ../pkg/config
