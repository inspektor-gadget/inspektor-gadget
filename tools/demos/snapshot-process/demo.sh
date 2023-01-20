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
source $(dirname ${BASH_SOURCE})/../util.sh


desc "Let's list the processes inside a pod"
run "kubectl get pod -n demo"
run "kubectl exec -n demo demo-pod-0 -- ps aux"
run "kubectl gadget snapshot process -n demo -p demo-pod-0"
desc "Inspektor Gadget is k8s aware as it gives us the node, namespace, pod and container where the process runs!"

desc "Let's list the processes inside all pods from the demo namespace!"
pods=$(kubectl get pod -n demo --no-headers | awk '{print $1}')
run "for i in {0..2}; do kubectl exec -n demo demo-pod-\$i -- ps aux; done"
desc "This time the command is not easy to write, let's see what Inspektor Gadget offers!"
run "kubectl gadget snapshot process -n demo"
desc "Wouah! This is more user friendly!"

desc "What about getting all the processes in the cluster?"
run "kubectl gadget snapshot process -A"
sleep 5
