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
operator-sdk init --domain kinvolk.io --repo github.com/inspektor-gadget/inspektor-gadget
cp ../hack/boilerplate.go.txt hack/boilerplate.go.txt
operator-sdk create api --group gadget --version v1alpha1 --kind Trace --resource --controller
make manifests

if [ "$1" = "gen" ] ; then
  mkdir -p ../pkg/apis/gadget/v1alpha1/
  cp -a api/v1alpha1/*.go ../pkg/apis/gadget/v1alpha1/

  cp -a main.go ../gadget-container/gadgettracermanager/controller.go

  mkdir -p ../pkg/controllers
  cp -a controllers/*.go ../pkg/controllers/

  mkdir -p ../pkg/resources/crd/bases
  cp -a config/crd/bases/gadget.kinvolk.io_traces.yaml ../pkg/resources/crd/bases/

  mkdir -p ../pkg/resources/rbac
  cp -a config/rbac/role.yaml ../pkg/resources/rbac/

  cd ..

  git add pkg/apis/gadget/v1alpha1/*.go
  git add gadget-container/gadgettracermanager/controller.go
  git add pkg/controllers/*.go
  git add pkg/resources/crd/bases/*.yaml
  git add pkg/resources/rbac/role.yaml
  git commit -m "New CRD and controller for Trace" -m "Commit generated automatically by hack/generate-gadget-operator.sh"
fi

if [ "$1" = "diff" ] ; then
  echo "Differences between newly generated files"
  diff -ur api ../pkg/api
  diff -ur controllers ../pkg/controllers
  diff -ur config ../pkg/resources
fi
