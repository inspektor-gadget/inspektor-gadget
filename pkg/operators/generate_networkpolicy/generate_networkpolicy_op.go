// Copyright 2025 The Inspektor Gadget authors
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

// Package generate_networkpolicy provides an operator that generates network policies
// based on the network traffic observed in the cluster.
// This is a temporary solution until we have a way of running gadget code on the client side
package generate_networkpolicy

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	name     = "GenerateNetworkPolicy"
	Priority = 9200
)

type gnpOperator struct{}

func (s *gnpOperator) Name() string {
	return name
}

func (s *gnpOperator) Init(params *params.Params) error {
	return nil
}

func (s *gnpOperator) GlobalParams() api.Params {
	return nil
}

func (s *gnpOperator) InstanceParams() api.Params {
	return nil
}

type k8sAccesors struct {
	k8sHostNetwork       datasource.FieldAccessor
	k8sNamespace         datasource.FieldAccessor
	k8sPodLabels         datasource.FieldAccessor
	k8sPodIP             datasource.FieldAccessor
	k8sPodName           datasource.FieldAccessor
	k8sOwnerName         datasource.FieldAccessor
	endpointAddr         datasource.FieldAccessor
	endpointPort         datasource.FieldAccessor
	endpointK8sKind      datasource.FieldAccessor
	endpointK8sName      datasource.FieldAccessor
	endpointK8sNamespace datasource.FieldAccessor
	endpointK8sLabels    datasource.FieldAccessor
	endpointProto        datasource.FieldAccessor
	egress               datasource.FieldAccessor

	adviseDS    datasource.DataSource
	adviseField datasource.FieldAccessor
}

func (s *gnpOperator) getAccessors(gadgetCtx operators.GadgetContext) (map[datasource.DataSource]k8sAccesors, error) {
	logger := gadgetCtx.Logger()
	accessors := make(map[datasource.DataSource]k8sAccesors)
	for _, ds := range gadgetCtx.GetDataSources() {
		logger.Debugf("GenerateNetworkPolicy inspecting datasource %q", ds.Name())

		if ds.Annotations()["generate_networkpolicy.enable"] != "true" {
			logger.Debugf("GenerateNetworkPolicy not enabled by annotation")
			continue
		}

		acc := k8sAccesors{}

		acc.k8sHostNetwork = ds.GetField("k8s.hostnetwork")
		if acc.k8sHostNetwork == nil {
			return nil, fmt.Errorf("no hostnetwork field found")
		}
		acc.k8sNamespace = ds.GetField("k8s.namespace")
		if acc.k8sNamespace == nil {
			return nil, fmt.Errorf("no namespace field found")
		}
		acc.k8sPodLabels = ds.GetField("k8s.podLabels")
		if acc.k8sPodLabels == nil {
			return nil, fmt.Errorf("no podLabels field found")
		}
		acc.k8sPodIP = ds.GetField("k8s.podIP")
		if acc.k8sPodIP == nil {
			return nil, fmt.Errorf("no podIP field found")
		}
		acc.k8sPodName = ds.GetField("k8s.podName")
		if acc.k8sPodName == nil {
			return nil, fmt.Errorf("no podName field found")
		}
		acc.k8sOwnerName = ds.GetField("k8s.owner.name")
		if acc.k8sOwnerName == nil {
			return nil, fmt.Errorf("no owner.name field found")
		}
		acc.endpointAddr = ds.GetField("endpoint.addr")
		if acc.endpointAddr == nil {
			return nil, fmt.Errorf("no endpoint.addr field found")
		}
		acc.endpointPort = ds.GetField("endpoint.port")
		if acc.endpointPort == nil {
			return nil, fmt.Errorf("no endpoint.port field found")
		}
		acc.endpointK8sKind = ds.GetField("endpoint.k8s.kind")
		if acc.endpointK8sKind == nil {
			return nil, fmt.Errorf("no endpoint.k8s.kind field found")
		}
		acc.endpointK8sName = ds.GetField("endpoint.k8s.name")
		if acc.endpointK8sName == nil {
			return nil, fmt.Errorf("no endpoint.k8s.name field found")
		}
		acc.endpointK8sNamespace = ds.GetField("endpoint.k8s.namespace")
		if acc.endpointK8sNamespace == nil {
			return nil, fmt.Errorf("no endpoint.k8s.namespace field found")
		}
		acc.endpointK8sLabels = ds.GetField("endpoint.k8s.labels")
		if acc.endpointK8sLabels == nil {
			return nil, fmt.Errorf("no endpoint.k8s.labels field found")
		}
		acc.endpointProto = ds.GetField("endpoint.proto")
		if acc.endpointProto == nil {
			return nil, fmt.Errorf("no endpoint.proto field found")
		}
		acc.egress = ds.GetField("egress")
		if acc.egress == nil {
			return nil, fmt.Errorf("no egress field found")
		}

		// Disable datasource for other operators
		ds.Unreference()

		var err error
		acc.adviseDS, err = gadgetCtx.RegisterDataSource(
			datasource.TypeSingle,
			fmt.Sprintf("advise-%s", ds.Name()),
		)
		if err != nil {
			return nil, fmt.Errorf("registering policies data source for %s: %w", acc.adviseDS.Name(), err)
		}
		gadgetCtx.Logger().Debugf("GenerateNetworkPolicy: registered ds %q", acc.adviseDS.Name())

		acc.adviseDS.AddAnnotation("cli.default-output-mode", "advise")
		acc.adviseDS.AddAnnotation("cli.supported-output-modes", "advise")

		acc.adviseField, err = acc.adviseDS.AddField("text", api.Kind_String)
		if err != nil {
			return nil, fmt.Errorf("adding field %q: %w", "text", err)
		}

		accessors[ds] = acc
	}
	return accessors, nil
}

func (s *gnpOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	accessors, err := s.getAccessors(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("getting accessors: %w", err)
	}
	if len(accessors) == 0 {
		gadgetCtx.Logger().Debug("GenerateNetworkPolicy: no datasources requiring the operator found")
		return nil, nil
	}
	return &gnpOperatorInstance{
		accessors: accessors,
	}, nil
}

func (s *gnpOperator) Priority() int {
	return Priority
}

type gnpOperatorInstance struct {
	accessors map[datasource.DataSource]k8sAccesors
}

func (s *gnpOperatorInstance) Name() string {
	return name + "Instance"
}

func (s *gnpOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, acc := range s.accessors {
		ds.SubscribeArray(func(source datasource.DataSource, packet datasource.DataArray) error {
			eventsBySource := map[string][]NetworkEvent{}
			for i := range packet.Len() {
				data := packet.Get(i)
				k8sLabelsRaw, _ := acc.k8sPodLabels.String(data)
				k8sLabelPairs := strings.Split(k8sLabelsRaw, ",")

				hostNetwork, _ := acc.k8sHostNetwork.Bool(data)
				if hostNetwork {
					continue
				}

				e := NetworkEvent{
					endpoint: types.L4Endpoint{
						L3Endpoint: types.L3Endpoint{
							PodLabels: map[string]string{},
						},
					},
					K8s: types.K8sMetadata{
						BasicK8sMetadata: types.BasicK8sMetadata{
							PodLabels: map[string]string{},
						},
					},
				}

				egressRaw, _ := acc.egress.Uint8(data)
				e.egress = egressRaw != 0
				e.endpoint.Addr, _ = acc.endpointAddr.String(data)
				e.endpoint.Port, _ = acc.endpointPort.Uint16(data)
				e.endpoint.Name, _ = acc.endpointK8sName.String(data)
				e.endpoint.Namespace, _ = acc.endpointK8sNamespace.String(data)
				e.proto, _ = acc.endpointProto.String(data)

				endpointEndpointStr, _ := acc.endpointK8sKind.String(data)
				e.endpoint.Kind = types.EndpointKind(endpointEndpointStr)

				endpointK8sPodLabelsRaw, _ := acc.endpointK8sLabels.String(data)
				endpointK8sLabelPairs := strings.Split(endpointK8sPodLabelsRaw, ",")
				for _, pair := range endpointK8sLabelPairs {
					kv := strings.Split(pair, "=")
					if len(kv) != 2 {
						continue
					}
					e.endpoint.PodLabels[kv[0]] = kv[1]
				}

				e.K8s.PodName, _ = acc.k8sPodName.String(data)
				e.K8s.Owner.Name, _ = acc.k8sOwnerName.String(data)
				e.K8s.HostNetwork = hostNetwork
				e.K8s.Namespace, _ = acc.k8sNamespace.String(data)
				for _, pair := range k8sLabelPairs {
					kv := strings.Split(pair, "=")
					if len(kv) != 2 {
						continue
					}
					e.K8s.PodLabels[kv[0]] = kv[1]
				}

				// Kubernetes Network Policies can't block traffic from a pod's
				// own resident node. Therefore we must not generate a network
				// policy in that case.
				podIP, _ := acc.k8sPodIP.String(data)
				if !e.egress && podIP == e.endpoint.Addr {
					continue
				}

				key := localPodKey(e)
				eventsBySource[key] = append(eventsBySource[key], e)
			}

			if len(eventsBySource) != 0 {
				// api.Warnf("Got %d events by source", len(eventsBySource))
				policies, err := handleEvents(eventsBySource)
				if err != nil {
					return fmt.Errorf("handling events: %w", err)
				}
				// api.Warnf("> Created %d policies", len(policies))
				policiesStr := FormatPolicies(policies)
				//// api.Warnf("> Policies:\n%s", policiesStr[:100])

				yamlPack, err := acc.adviseDS.NewPacketSingle()
				if err != nil {
					return fmt.Errorf("creating packet: %w", err)
				}
				acc.adviseField.PutString(yamlPack, policiesStr)
				acc.adviseDS.EmitAndRelease(yamlPack)
			}
			return nil
		}, 0)
	}
	return nil
}

func (s *gnpOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (s *gnpOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

var GNPOperator = &gnpOperator{}
