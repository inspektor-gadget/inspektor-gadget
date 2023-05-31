// Copyright 2022-2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containercollection

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func (cc *ContainerCollection) EnrichEventByMntNs(event operators.ContainerInfoFromMountNSID) {
	event.SetNode(cc.nodeName)

	container := cc.LookupContainerByMntns(event.GetMountNSID())
	if container != nil {
		event.SetContainerInfo(container.K8s.Pod, container.K8s.Namespace, container.K8s.Container)
	}
}

func (cc *ContainerCollection) EnrichEventByNetNs(event operators.ContainerInfoFromNetNSID) {
	event.SetNode(cc.nodeName)

	containers := cc.LookupContainersByNetns(event.GetNetNSID())
	if len(containers) == 0 || containers[0].HostNetwork {
		return
	}
	if len(containers) == 1 {
		event.SetContainerInfo(containers[0].K8s.Pod, containers[0].K8s.Namespace, containers[0].K8s.Container)
		return
	}
	if containers[0].K8s.Pod != "" && containers[0].K8s.Namespace != "" {
		// Kubernetes containers within the same pod.
		event.SetContainerInfo(containers[0].K8s.Pod, containers[0].K8s.Namespace, "")
	}
	// else {
	// 	TODO: Non-Kubernetes containers sharing the same network namespace.
	// 	What should we do here?
	// }

	return
}
