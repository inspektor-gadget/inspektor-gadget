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
	"errors"
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	OperatorName = "KubeIPResolver"
	Priority     = 10
)

const (
	endpointL4Type = "gadget_l4endpoint_t"
	ipAddrType     = "gadget_ip_addr_t"
)

type KubeIPResolverInterface interface {
	GetEndpoints() []*types.L3Endpoint
}

type KubeIPResolver struct{}

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

func (k *KubeIPResolver) Init(params *params.Params) error {
	return nil
}

func (k *KubeIPResolver) Close() error {
	return nil
}

func (k *KubeIPResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
	}

	return &KubeIPResolverInstance{
		gadgetCtx:      gadgetCtx,
		k8sInventory:   k8sInventory,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeIPResolverInstance struct {
	gadgetCtx          operators.GadgetContext
	k8sInventory       common.K8sInventoryCache
	gadgetInstance     any
	endpointsAccessors map[datasource.DataSource][]endpointAccessors
}

func (m *KubeIPResolverInstance) Name() string {
	return "KubeIPResolverInstance"
}

func (m *KubeIPResolverInstance) PreGadgetRun() error {
	m.k8sInventory.Start()
	return nil
}

func (m *KubeIPResolverInstance) PostGadgetRun() error {
	m.k8sInventory.Stop()
	return nil
}

func (m *KubeIPResolverInstance) enrich(ev any) {
	endpoints := ev.(KubeIPResolverInterface).GetEndpoints()
	for _, endpoint := range endpoints {
		endpoint.Kind = types.EndpointKindRaw

		pod := m.k8sInventory.GetPodByIp(endpoint.Addr)
		if pod != nil {
			if pod.Spec.HostNetwork {
				continue
			}
			endpoint.Kind = types.EndpointKindPod
			endpoint.Name = pod.Name
			endpoint.Namespace = pod.Namespace
			endpoint.PodLabels = pod.Labels
			continue
		}

		svc := m.k8sInventory.GetSvcByIp(endpoint.Addr)
		if svc != nil {
			endpoint.Kind = types.EndpointKindService
			endpoint.Name = svc.Name
			endpoint.Namespace = svc.Namespace
			endpoint.PodLabels = svc.Labels
		}
	}
}

func (m *KubeIPResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func (k *KubeIPResolver) GlobalParams() api.Params {
	return nil
}

func (k *KubeIPResolver) InstanceParams() api.Params {
	return nil
}

type endpointAccessors struct {
	root            datasource.FieldAccessor
	subK8sKind      datasource.FieldAccessor
	subK8sName      datasource.FieldAccessor
	subK8sNamespace datasource.FieldAccessor
	subK8sLabels    datasource.FieldAccessor

	column datasource.FieldAccessor
	port   datasource.FieldAccessor
}

func (k *KubeIPResolver) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	logger := gadgetCtx.Logger()
	epAccessors := make(map[datasource.DataSource][]endpointAccessors)
	for _, ds := range gadgetCtx.GetDataSources() {
		logger.Debugf("KubeIPResolverOperator inspecting datasource %q", ds.Name())

		endpoints := ds.GetFieldsWithTag("type:" + endpointL4Type)
		if len(endpoints) == 0 {
			logger.Debugf("> no endpoint fields found")
			continue
		}

		logger.Debugf("> found %d endpoint fields", len(endpoints))
		for _, ep := range endpoints {
			// validate the endpoint fields
			ips := ep.GetSubFieldsWithTag("type:" + ipAddrType)
			if len(ips) != 1 {
				return nil, fmt.Errorf("%s: expected %d %q field, got %d", ep.Name(), 1, ipAddrType, len(ips))
			}

			if ips[0].Size() != 16 {
				return nil, fmt.Errorf("%s: expected %q field to have size %d, got %d", ep.Name(), ipAddrType, 16, ips[0].Size())
			}

			version := ep.GetSubFieldsWithTag("name:version")
			if len(version) != 1 {
				return nil, fmt.Errorf("%s: expected %d %q field, got %d", ep.Name(), 1, "version", len(version))
			}

			// Add subfields for k8s metadata to the endpoint
			k8sSubAcc, err := ep.AddSubField("k8s", api.Kind_Invalid, datasource.WithFlags(datasource.FieldFlagEmpty))
			if err != nil {
				return nil, fmt.Errorf("adding field %q: %w", "k8s", err)
			}
			k8sKindAcc, err := k8sSubAcc.AddSubField("kind", api.Kind_String,
				datasource.WithAnnotations(map[string]string{
					metadatav1.ColumnsMaxWidthAnnotation: "12",
				}),
				datasource.WithFlags(datasource.FieldFlagHidden),
			)
			if err != nil {
				return nil, fmt.Errorf("adding field %q: %w", "kind", err)
			}
			k8sNameAcc, err := k8sSubAcc.AddSubField("name",
				api.Kind_String,
				datasource.WithAnnotations(map[string]string{
					metadatav1.TemplateAnnotation: "pod",
				}),
				datasource.WithFlags(datasource.FieldFlagHidden),
			)
			if err != nil {
				return nil, fmt.Errorf("adding field %q: %w", "name", err)
			}
			k8sNamespaceAcc, err := k8sSubAcc.AddSubField("namespace",
				api.Kind_String,
				datasource.WithAnnotations(map[string]string{
					metadatav1.TemplateAnnotation: "namespace",
				}),
				datasource.WithFlags(datasource.FieldFlagHidden),
			)
			if err != nil {
				return nil, fmt.Errorf("adding field %q: %w", "namespace", err)
			}
			k8sLabelsAcc, err := k8sSubAcc.AddSubField("labels", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
			if err != nil {
				return nil, fmt.Errorf("adding field %q: %w", "labels", err)
			}

			// control how the field is displayed
			var endpointColAcc datasource.FieldAccessor
			if ec := ep.GetSubFieldsWithTag("endpoint"); len(ec) == 1 {
				endpointColAcc = ec[0]
			}
			var portAcc datasource.FieldAccessor
			if p := ep.GetSubFieldsWithTag("name:port"); len(p) == 1 && p[0].Size() == 2 {
				portAcc = p[0]
			}

			ea := endpointAccessors{
				root:            ep,
				subK8sKind:      k8sKindAcc,
				subK8sName:      k8sNameAcc,
				subK8sNamespace: k8sNamespaceAcc,
				subK8sLabels:    k8sLabelsAcc,
				column:          endpointColAcc,
				port:            portAcc,
			}
			epAccessors[ds] = append(epAccessors[ds], ea)
		}
	}

	// No endpoints found, nothing to do
	if len(epAccessors) == 0 {
		return nil, nil
	}

	k8sInventory, err := common.GetK8sInventoryCache()
	if err != nil {
		return nil, fmt.Errorf("creating k8s inventory cache: %w", err)
	}

	return &KubeIPResolverInstance{
		k8sInventory:       k8sInventory,
		endpointsAccessors: epAccessors,
	}, nil
}

func (k *KubeIPResolver) Priority() int {
	return Priority
}

func (m *KubeIPResolverInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	m.k8sInventory.Start()
	return nil
}

func (m *KubeIPResolverInstance) Start(gadgetCtx operators.GadgetContext) error {
	for ds, acc := range m.endpointsAccessors {
		ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
			var errs error
			for _, a := range acc {
				ip := a.root.GetSubFieldsWithTag("type:" + ipAddrType)[0]
				version := a.root.GetSubFieldsWithTag("name:version")[0]
				addrStr, err := common.GetIPForVersion(data, version, ip)
				if err != nil {
					errors.Join(errs, fmt.Errorf("%s: getting IP: %w", a.root.Name(), err))
					continue
				}

				pod := m.k8sInventory.GetPodByIp(addrStr)
				if pod != nil {
					if pod.Spec.HostNetwork {
						continue
					}
					a.subK8sName.Set(data, []byte(pod.Name))
					a.subK8sKind.Set(data, []byte("pod"))
					a.subK8sNamespace.Set(data, []byte(pod.Namespace))
					// TODO: labels should be a map/slice
					var labels []string
					for key, val := range pod.Labels {
						labels = append(labels, fmt.Sprintf("%s=%s", key, val))
					}
					a.subK8sLabels.Set(data, []byte(strings.Join(labels, ",")))
					if a.column != nil && a.port != nil {
						p, _ := a.port.Uint16(data)
						v := fmt.Sprintf("p/%s/%s:%d", pod.Namespace, pod.Name, p)
						a.column.Set(data, []byte(v))
					}
					continue
				}

				svc := m.k8sInventory.GetSvcByIp(addrStr)
				if svc != nil {
					a.subK8sKind.Set(data, []byte("svc"))
					a.subK8sName.Set(data, []byte(svc.Name))
					a.subK8sNamespace.Set(data, []byte(svc.Namespace))
					// TODO: labels should be a map/slice
					var labels []string
					for key, val := range svc.Labels {
						labels = append(labels, fmt.Sprintf("%s=%s", key, val))
					}
					a.subK8sLabels.Set(data, []byte(strings.Join(labels, ",")))

					if a.column != nil && a.port != nil {
						p, _ := a.port.Uint16(data)
						v := fmt.Sprintf("s/%s/%s:%d", svc.Namespace, svc.Name, p)
						a.column.Set(data, []byte(v))
					}
					continue
				}

				a.subK8sKind.Set(data, []byte("raw"))
			}
			return errs
		}, Priority)
	}
	return nil
}

func (m *KubeIPResolverInstance) PostStop(gadgetCtx operators.GadgetContext) error {
	m.k8sInventory.Stop()
	return nil
}

func (m *KubeIPResolverInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.Register(&KubeIPResolver{})
	operators.RegisterDataOperator(&KubeIPResolver{})
}
