#!/bin/bash
# Copyright 2016 The Kubernetes Authors.
# Copyright 2022 The Inspektor Gadget authors
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

. $(dirname ${BASH_SOURCE})/../util.sh

desc "Let's start a pod that's using the filesystem"
run "kubectl run -n demo test-pod --image ubuntu -- sh -c 'while true ; do tar cf /var/archive.tar /usr ; rm -f /var/archive.tar; done'"
run "kubectl wait -n demo --for=condition=ready pod/test-pod"

desc "Let's trace"
run "kubectl gadget trace fsslower -n demo -f ext4 -m 1 --timeout 5"

sleep 5
