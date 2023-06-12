// Copyright 2023 The Inspektor Gadget authors
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

// Package kubenameresolver provides an operator that enriches events by looking
// up the pod name and namespace and enriches it with its ip information. It is
// currently used by the following gadgets:
// - trace network
package kubenameresolver

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName = "KubeNameResolver"
)

type KubeNameResolverInterface interface {
	SetLocalPodDetails(owner, hostIP, podIP string, labels map[string]string)
}

type KubeNameResolver struct {
	k8sInventory *common.K8sInventoryCache
}

func (k *KubeNameResolver) Name() string {
	return OperatorName
}

func (k *KubeNameResolver) Description() string {
	return "KubeNameResolver resolves pod name/namespace to IP addresses"
}

func (k *KubeNameResolver) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeNameResolver) ParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeNameResolver) Dependencies() []string {
	return []string{kubemanager.OperatorName}
}

func (k *KubeNameResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	km := kubemanager.KubeManager{}
	if !km.CanOperateOn(gadget) {
		return false
	}
	_, hasNameResolverInterface := gadget.EventPrototype().(KubeNameResolverInterface)
	return hasNameResolverInterface
}

func (k *KubeNameResolver) Init(params *params.Params) error {
	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return fmt.Errorf("creating k8s inventory cache: %w", err)
	}
	k.k8sInventory = k8sInventory
	return nil
}

func (k *KubeNameResolver) Close() error {
	k.k8sInventory.Close()
	return nil
}

func (k *KubeNameResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	return &KubeNameResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeNameResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *KubeNameResolver
	gadgetInstance any
}

func (m *KubeNameResolverInstance) Name() string {
	return "KubeNameResolverInstance"
}

func (m *KubeNameResolverInstance) PreGadgetRun() error {
	m.manager.k8sInventory.Start()
	return nil
}

func (m *KubeNameResolverInstance) PostGadgetRun() error {
	m.manager.k8sInventory.Stop()
	return nil
}

func (m *KubeNameResolverInstance) enrich(ev any) {
	kubeNameResolver, _ := ev.(KubeNameResolverInterface)
	containerInfo, _ := ev.(operators.ContainerInfoGetters)

	pods := m.manager.k8sInventory.GetPods()
	for i, pod := range pods.Items {
		if pod.Namespace == containerInfo.GetNamespace() && pod.Name == containerInfo.GetPod() {
			owner := ""
			// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
			// shorter name without the random suffix. That will be used to
			// generate the network policy name.
			if pods.Items[i].OwnerReferences != nil {
				nameItems := strings.Split(pods.Items[i].Name, "-")
				if len(nameItems) > 2 {
					owner = strings.Join(nameItems[:len(nameItems)-2], "-")
				}
			}
			kubeNameResolver.SetLocalPodDetails(owner, pod.Status.HostIP, pod.Status.PodIP, pod.Labels)
			return
		}
	}
}

func (m *KubeNameResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeNameResolver{})
}
