#!/usr/bin/env bash

# Copyright 2017 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

TEMP=$(mktemp -d)
cp -r "${SCRIPT_ROOT}"/hack/ ${TEMP}

pushd ${TEMP}

go mod init tmp

echo "require k8s.io/code-generator v0.21.2" >> go.mod

go get tmp/hack
go mod vendor

popd

bash ${TEMP}/vendor/k8s.io/code-generator/generate-groups.sh "client" \
  github.com/inspektor-gadget/inspektor-gadget/pkg/client github.com/inspektor-gadget/inspektor-gadget/pkg/apis \
  gadget:v1alpha1 \
  --output-base ${TEMP} \
  --go-header-file "${SCRIPT_ROOT}"/hack/boilerplate.go.txt

cp -r ${TEMP}/github.com/inspektor-gadget/inspektor-gadget/pkg/client/ ${SCRIPT_ROOT}/pkg/
rm -rf ${TEMP}
