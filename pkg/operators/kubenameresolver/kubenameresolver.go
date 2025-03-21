// Copyright 2023-2025 The Inspektor Gadget authors
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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName = "KubeNameResolver"
	Priority     = 11
)

type KubeNameResolverInterface interface {
	SetLocalPodDetails(owner, hostIP, podIP string, labels map[string]string)
}

type KubeNameResolver struct{}

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
	return nil
}

func (k *KubeNameResolver) Close() error {
	return nil
}

func (k *KubeNameResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
	}

	return &KubeNameResolverInstance{
		gadgetCtx:      gadgetCtx,
		k8sInventory:   k8sInventory,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeNameResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	k8sInventory   common.K8sInventoryCache
	accessors      map[datasource.DataSource]k8sAccesors
	gadgetInstance any
}

func (m *KubeNameResolverInstance) Name() string {
	return "KubeNameResolverInstance"
}

func (m *KubeNameResolverInstance) PreGadgetRun() error {
	m.k8sInventory.Start()
	return nil
}

func (m *KubeNameResolverInstance) PostGadgetRun() error {
	m.k8sInventory.Stop()
	return nil
}

func (m *KubeNameResolverInstance) enrich(ev any) {
	kubeNameResolver, _ := ev.(KubeNameResolverInterface)
	containerInfo, _ := ev.(operators.ContainerInfoGetters)

	pod := m.k8sInventory.GetPodByName(containerInfo.GetNamespace(), containerInfo.GetPod())
	if pod != nil {
		owner := ""
		// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
		// shorter name without the random suffix. That will be used to
		// generate the network policy name.
		if pod.OwnerReferences != nil {
			nameItems := strings.Split(pod.Name, "-")
			if len(nameItems) > 2 {
				owner = strings.Join(nameItems[:len(nameItems)-2], "-")
			}
		}
		kubeNameResolver.SetLocalPodDetails(owner, pod.Status.HostIP, pod.Status.PodIP, pod.Labels)
	}
}

func (m *KubeNameResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func (k *KubeNameResolver) GlobalParams() api.Params {
	return nil
}

func (k *KubeNameResolver) InstanceParams() api.Params {
	return nil
}

func (k *KubeNameResolver) Priority() int {
	return Priority
}

type k8sAccesors struct {
	PodName   datasource.FieldAccessor
	Namespace datasource.FieldAccessor
	Owner     datasource.FieldAccessor
	PodIP     datasource.FieldAccessor
	HostIP    datasource.FieldAccessor
	PodLabels datasource.FieldAccessor
}

func (k *KubeNameResolver) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	logger := gadgetCtx.Logger()
	accessors := make(map[datasource.DataSource]k8sAccesors)
	for _, ds := range gadgetCtx.GetDataSources() {
		logger.Debugf("KubeNameResolverOperator inspecting datasource %q", ds.Name())

		k8sField := ds.GetField("k8s")
		if k8sField == nil {
			logger.Debugf("> no k8s fields found")
			continue
		}

		k8sAccesors := k8sAccesors{}
		var err error

		k8sAccesors.PodName = ds.GetField("k8s.podName")
		if k8sAccesors.PodName == nil {
			logger.Warnf("No podName field found in datasource %q", ds.Name())
			continue
		}

		k8sAccesors.Namespace = ds.GetField("k8s.namespace")
		if k8sAccesors.Namespace == nil {
			logger.Warnf("No namespace field found in datasource %q", ds.Name())
			continue
		}

		k8sAccesors.Owner = ds.GetField("k8s.owner")
		if k8sAccesors.Owner == nil {
			logger.Warnf("No owner field found in datasource %q", ds.Name())
			continue
		}

		k8sAccesors.PodLabels = ds.GetField("k8s.podLabels")
		if k8sAccesors.PodLabels == nil {
			logger.Warnf("No podLabels field found in datasource %q", ds.Name())
			continue
		}

		// Create 2 new fields
		k8sAccesors.HostIP, err = k8sField.AddSubField("hostIP", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
		if err != nil {
			return nil, fmt.Errorf("adding field %q: %w", "hostIP", err)
		}
		k8sAccesors.PodIP, err = k8sField.AddSubField("podIP", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
		if err != nil {
			return nil, fmt.Errorf("adding field %q: %w", "podIP", err)
		}

		logger.Debugf("> Found fields for DS %q", ds.Name())
		accessors[ds] = k8sAccesors
	}

	// No endpoints found, nothing to do
	if len(accessors) == 0 {
		return nil, nil
	}

	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
	}

	return &KubeNameResolverInstance{
		k8sInventory: k8sInventory,
		accessors:    accessors,
	}, nil
}

func (m *KubeNameResolverInstance) enrichSingle(data datasource.Data, accessor k8sAccesors) {
	podName, _ := accessor.PodName.String(data)
	namespace, _ := accessor.Namespace.String(data)

	pod := m.k8sInventory.GetPodByName(namespace, podName)
	if pod != nil {
		owner := ""
		// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
		// shorter name without the random suffix. That will be used to
		// generate the network policy name.
		if pod.OwnerReferences != nil {
			nameItems := strings.Split(pod.Name, "-")
			if len(nameItems) > 2 {
				owner = strings.Join(nameItems[:len(nameItems)-2], "-")
			}
		}

		accessor.HostIP.PutString(data, pod.Status.HostIP)
		accessor.PodIP.PutString(data, pod.Status.PodIP)
		accessor.Owner.PutString(data, owner)

		labelKeyValuePairs := make([]string, 0, len(pod.Labels))
		for k, v := range pod.Labels {
			labelKeyValuePairs = append(labelKeyValuePairs, fmt.Sprintf("%s=%s", k, v))
		}
		accessor.PodLabels.PutString(data, strings.Join(labelKeyValuePairs, ","))
	}
}

func (m *KubeNameResolverInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	m.k8sInventory.Start()

	for ds, accessor := range m.accessors {
		ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
			m.enrichSingle(data, accessor)
			return nil
		}, Priority)
	}

	return nil
}

func (m *KubeNameResolverInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *KubeNameResolverInstance) PostStop(gadgetCtx operators.GadgetContext) error {
	m.k8sInventory.Stop()
	return nil
}

func (m *KubeNameResolverInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.Register(&KubeNameResolver{})
	operators.RegisterDataOperator(&KubeNameResolver{})
}
