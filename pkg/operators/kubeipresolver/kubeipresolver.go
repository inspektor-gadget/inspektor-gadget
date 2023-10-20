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

// Package kubeipresolver provides an operator that enriches events by looking
// up IP addresses in Kubernetes resources such as pods and services.
package kubeipresolver

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	OperatorName = "KubeIPResolver"
)

type KubeIPResolverInterface interface {
	GetEndpoints() []*types.L3Endpoint
}

type KubeIPResolver struct {
	k8sInventory *common.K8sInventoryCache
}

func (k *KubeIPResolver) Name() string {
	return OperatorName
}

func (k *KubeIPResolver) Description() string {
	return "KubeIPResolver resolves IP addresses to pod and service names"
}

func (k *KubeIPResolver) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeIPResolver) ParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeIPResolver) Dependencies() []string {
	return nil
}

func (k *KubeIPResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	_, hasIPResolverInterface := gadget.EventPrototype().(KubeIPResolverInterface)
	return hasIPResolverInterface
}

func (k *KubeIPResolver) CanOperateOnContainerizedGadget(info *runTypes.GadgetInfo) bool {
	return info.Features.HasEndpoints
}

func (k *KubeIPResolver) Init(params *params.Params) error {
	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return fmt.Errorf("creating k8s inventory cache: %w", err)
	}
	k.k8sInventory = k8sInventory
	return nil
}

func (k *KubeIPResolver) Close() error {
	k.k8sInventory.Close()
	return nil
}

func (k *KubeIPResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	return &KubeIPResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeIPResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *KubeIPResolver
	gadgetInstance any
}

func (m *KubeIPResolverInstance) Name() string {
	return "KubeIPResolverInstance"
}

func (m *KubeIPResolverInstance) PreGadgetRun() error {
	m.manager.k8sInventory.Start()
	return nil
}

func (m *KubeIPResolverInstance) PostGadgetRun() error {
	m.manager.k8sInventory.Stop()
	return nil
}

func (m *KubeIPResolverInstance) enrich(ev any) {
	pods := m.manager.k8sInventory.GetPods()
	endpoints := ev.(KubeIPResolverInterface).GetEndpoints()
	for j := range endpoints {
		// initialize to this default value if we don't find a match
		endpoints[j].Kind = types.EndpointKindRaw
	}

	found := 0
	for _, pod := range pods.Items {
		if pod.Spec.HostNetwork {
			continue
		}

		for _, endpoint := range endpoints {
			if pod.Status.PodIP == endpoint.Addr {
				endpoint.Kind = types.EndpointKindPod
				endpoint.Name = pod.Name
				endpoint.Namespace = pod.Namespace
				endpoint.PodLabels = pod.Labels

				found++
				if found == len(endpoints) {
					return
				}
			}
		}
	}

	svcs := m.manager.k8sInventory.GetSvcs()

	for _, svc := range svcs.Items {
		for _, endpoint := range endpoints {
			if svc.Spec.ClusterIP == endpoint.Addr {
				endpoint.Kind = types.EndpointKindService
				endpoint.Name = svc.Name
				endpoint.Namespace = svc.Namespace
				endpoint.PodLabels = svc.Labels

				found++
				if found == len(endpoints) {
					return
				}
			}
		}
	}
}

func (m *KubeIPResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeIPResolver{})
}
