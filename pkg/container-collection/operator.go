// Copyright 2022-2024 The Inspektor Gadget authors
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

	mountNsId := event.GetMountNSID()
	container := cc.LookupContainerByMntns(mountNsId)
	if container == nil && cc.cachedContainers != nil {
		container = lookupContainerByMntns(cc.cachedContainers, mountNsId)
	}
	if container != nil {
		event.SetContainerMetadata(container)
	}
}

func (cc *ContainerCollection) EnrichEventByNetNs(event operators.ContainerInfoFromNetNSID) {
	event.SetNode(cc.nodeName)

	netNsId := event.GetNetNSID()
	containers := cc.LookupContainersByNetns(netNsId)
	if len(containers) == 0 {
		containers = lookupContainersByNetns(cc.cachedContainers, netNsId)
	}
	if len(containers) == 0 || containers[0].HostNetwork {
		return
	}
	if len(containers) == 1 {
		event.SetContainerMetadata(containers[0])
		return
	}
	if containers[0].K8s.PodName != "" && containers[0].K8s.Namespace != "" {
		// Kubernetes containers within the same pod.
		event.SetPodMetadata(containers[0])
	}
	// else {
	// 	TODO: Non-Kubernetes containers sharing the same network namespace.
	// 	What should we do here?
	// }
}
