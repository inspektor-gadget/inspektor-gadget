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

package main

import (
	"fmt"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var (
	textds    api.DataSource
	textField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	textds, err = api.NewDataSource("advise", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %s", err)
		return 1
	}

	textField, err = textds.AddField("text", api.Kind_String)
	if err != nil {
		api.Errorf("adding field: %s", err)
		return 1
	}

	return 0
}

type NetworkEvent struct {
	K8s types.K8sMetadata

	egress   bool
	endpoint types.L4Endpoint
	proto    string // L4Endpoint has proto as uint8, but we need a string here
}

var defaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": {},
	"pod-template-generation":  {},
	"pod-template-hash":        {},
}

// TODO configurable?
var LabelsToIgnore = defaultLabelsToIgnore

/* labelFilteredKeyList returns a sorted list of label keys but without the labels to
 * ignore.
 */
func labelFilteredKeyList(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if _, ok := LabelsToIgnore[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

func labelFilter(labels map[string]string) map[string]string {
	ret := map[string]string{}
	for k := range labels {
		if _, ok := LabelsToIgnore[k]; ok {
			continue
		}
		ret[k] = labels[k]
	}
	return ret
}

/* labelKeyString returns a sorted list of labels in a single string.
 * label1=value1,label2=value2
 */
func labelKeyString(labels map[string]string) (ret string) {
	keys := labelFilteredKeyList(labels)

	for index, k := range keys {
		sep := ","
		if index == 0 {
			sep = ""
		}
		ret += fmt.Sprintf("%s%s=%s", sep, k, labels[k])
	}
	return
}

/* localPodKey returns a key that can be used to group pods together:
 * namespace:label1=value1,label2=value2
 */
func localPodKey(e NetworkEvent) (ret string) {
	return e.K8s.Namespace + ":" + labelKeyString(e.K8s.PodLabels)
}

func networkPeerKey(e NetworkEvent) (ret string) {
	if e.endpoint.Kind == types.EndpointKindPod {
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodLabels)
	} else if e.endpoint.Kind == types.EndpointKindService {
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodLabels)
	} else if e.endpoint.Kind == types.EndpointKindRaw {
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Addr
	} else {
		api.Errorf("unknown endpoint kind: %s", e.endpoint.Kind)
	}
	return fmt.Sprintf("%s:%d", ret, e.endpoint.Port)
}

func eventToRule(e NetworkEvent) (ports []networkingv1.NetworkPolicyPort, peers []networkingv1.NetworkPolicyPeer) {
	port := intstr.FromInt(int(e.endpoint.Port))
	protocol := v1.Protocol(e.proto)
	ports = []networkingv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &protocol,
		},
	}
	if e.endpoint.Kind == types.EndpointKindPod {
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: labelFilter(e.endpoint.PodLabels)},
			},
		}
		if e.K8s.Namespace != e.endpoint.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.endpoint.Namespace,
				},
			}
		}
	} else if e.endpoint.Kind == types.EndpointKindService {
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: e.endpoint.PodLabels},
			},
		}
		if e.K8s.Namespace != e.endpoint.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.endpoint.Namespace,
				},
			}
		}
	} else if e.endpoint.Kind == types.EndpointKindRaw {
		if e.endpoint.Addr == "127.0.0.1" {
			// No need to generate a network policy for localhost
			peers = []networkingv1.NetworkPolicyPeer{}
		} else {
			peers = []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: e.endpoint.Addr + "/32",
					},
				},
			}
		}
	} else {
		api.Errorf("unknown endpoint kind: %s", e.endpoint.Kind)
		panic("unknown event")
	}
	return
}

func sortIngressRules(rules []networkingv1.NetworkPolicyIngressRule) []networkingv1.NetworkPolicyIngressRule {
	sort.Slice(rules, func(i, j int) bool {
		ri, rj := rules[i], rules[j]

		// No need to support all network policies, but only the ones
		// generated by eventToRule()
		if len(ri.Ports) != 1 || len(rj.Ports) != 1 {
			panic("rules with multiple ports")
		}
		if ri.Ports[0].Protocol == nil || rj.Ports[0].Protocol == nil {
			panic("rules without protocol")
		}

		switch {
		case *ri.Ports[0].Protocol != *rj.Ports[0].Protocol:
			return *ri.Ports[0].Protocol < *rj.Ports[0].Protocol
		case ri.Ports[0].Port.IntVal != rj.Ports[0].Port.IntVal:
			return ri.Ports[0].Port.IntVal < rj.Ports[0].Port.IntVal
		default:
			yamlOutput1, _ := k8syaml.Marshal(ri)
			yamlOutput2, _ := k8syaml.Marshal(rj)
			return string(yamlOutput1) < string(yamlOutput2)
		}
	})
	return rules
}

func sortEgressRules(rules []networkingv1.NetworkPolicyEgressRule) []networkingv1.NetworkPolicyEgressRule {
	sort.Slice(rules, func(i, j int) bool {
		ri, rj := rules[i], rules[j]

		// No need to support all network policies, but only the ones
		// generated by eventToRule()
		if len(ri.Ports) != 1 || len(rj.Ports) != 1 {
			panic("rules with multiple ports")
		}
		if ri.Ports[0].Protocol == nil || rj.Ports[0].Protocol == nil {
			panic("rules without protocol")
		}

		switch {
		case *ri.Ports[0].Protocol != *rj.Ports[0].Protocol:
			return *ri.Ports[0].Protocol < *rj.Ports[0].Protocol
		case ri.Ports[0].Port.IntVal != rj.Ports[0].Port.IntVal:
			return ri.Ports[0].Port.IntVal < rj.Ports[0].Port.IntVal
		default:
			yamlOutput1, _ := k8syaml.Marshal(ri)
			yamlOutput2, _ := k8syaml.Marshal(rj)
			return string(yamlOutput1) < string(yamlOutput2)
		}
	})
	return rules
}

func handleEvents(eventsBySource map[string][]NetworkEvent) []networkingv1.NetworkPolicy {
	policies := make([]networkingv1.NetworkPolicy, 0, len(eventsBySource))

	for _, events := range eventsBySource {
		egressNetworkPeer := map[string]NetworkEvent{}
		ingressNetworkPeer := map[string]NetworkEvent{}
		for _, e := range events {
			key := networkPeerKey(e)
			// api.Warnf("key for event with kind %s: %s", e.endpoint.Kind, key)
			if e.egress {
				if _, ok := egressNetworkPeer[key]; ok {
					// api.Warnf("duplicate egress network peer: %s", key)
					continue
				}
				egressNetworkPeer[key] = e
			} else {
				if _, ok := ingressNetworkPeer[key]; ok {
					// api.Warnf("duplicate ingress network peer: %s", key)
					continue
				}
				ingressNetworkPeer[key] = e
			}
		}
		// api.Warnf("> Found %d egress network peers", len(egressNetworkPeer))
		// api.Warnf("> Found %d ingress network peers", len(ingressNetworkPeer))

		egressPolicies := []networkingv1.NetworkPolicyEgressRule{}
		for _, p := range egressNetworkPeer {
			ports, peers := eventToRule(p)
			if len(peers) > 0 {
				rule := networkingv1.NetworkPolicyEgressRule{
					Ports: ports,
					To:    peers,
				}
				egressPolicies = append(egressPolicies, rule)
			}
		}
		ingressPolicies := []networkingv1.NetworkPolicyIngressRule{}
		for _, p := range ingressNetworkPeer {
			ports, peers := eventToRule(p)
			if len(peers) > 0 {
				rule := networkingv1.NetworkPolicyIngressRule{
					Ports: ports,
					From:  peers,
				}
				ingressPolicies = append(ingressPolicies, rule)
			}
		}

		name := events[0].K8s.PodName
		if events[0].K8s.Owner.Name != "" {
			name = events[0].K8s.Owner.Name
		}
		name += "-network"
		policy := networkingv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "NetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: events[0].K8s.Namespace,
				Labels:    map[string]string{},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: labelFilter(events[0].K8s.PodLabels)},
				PolicyTypes: []networkingv1.PolicyType{"Ingress", "Egress"},
				Ingress:     sortIngressRules(ingressPolicies),
				Egress:      sortEgressRules(egressPolicies),
			},
		}
		policies = append(policies, policy)
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	return policies
}

func FormatPolicies(policies []networkingv1.NetworkPolicy) (out string) {
	for i, p := range policies {
		// api.Warnf("policy %d: %s", i, p.Name)
		yamlOutput, err := k8syaml.Marshal(p)
		if err != nil {
			// api.Warnf("marshalling policy: %s", err)
			continue
		}
		sep := "---\n"
		if i == len(policies)-1 {
			sep = ""
		}
		out += fmt.Sprintf("%s%s", string(yamlOutput), sep)
	}
	return
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	events, err := api.GetDataSource("events")
	if err != nil {
		api.Errorf("getting datasource: %s", err)
		return 1
	}

	// K8s
	k8sHostNetworkField, err := events.GetField("k8s.hostnetwork")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	k8sNamespaceField, err := events.GetField("k8s.namespace")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	k8sPodLabelsField, err := events.GetField("k8s.podLabels")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	k8sPodIPField, err := events.GetField("k8s.podIP")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	k8sPodNameField, err := events.GetField("k8s.podName")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	k8sOwnerNameField, err := events.GetField("k8s.owner.name")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}

	// Endpoint
	endpointAddrField, err := events.GetField("endpoint.addr")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointPortField, err := events.GetField("endpoint.port")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointK8sKindField, err := events.GetField("endpoint.k8s.kind")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointK8sNameField, err := events.GetField("endpoint.k8s.name")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointK8sNamespaceField, err := events.GetField("endpoint.k8s.namespace")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointK8sLabelsField, err := events.GetField("endpoint.k8s.labels")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}
	endpointProtoField, err := events.GetField("endpoint.proto")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}

	egressField, err := events.GetField("egress")
	if err != nil {
		api.Errorf("getting field: %s", err)
		return 1
	}

	err = events.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		// api.Warnf("Got %d events", dataArr.Len())
		eventsBySource := map[string][]NetworkEvent{}
		for i := range dataArr.Len() {
			data := dataArr.Get(i)

			k8sLabelsRaw, _ := k8sPodLabelsField.String(data, 1024)
			k8sLabelPairs := strings.Split(k8sLabelsRaw, ",")

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

			egressRaw, _ := egressField.Uint8(data)
			e.egress = egressRaw != 1
			e.endpoint.Addr, _ = endpointAddrField.String(data, 15)
			e.endpoint.Port, _ = endpointPortField.Uint16(data)
			e.endpoint.Name, _ = endpointK8sNameField.String(data, 128)
			e.endpoint.Namespace, _ = endpointK8sNamespaceField.String(data, 128)
			e.proto, _ = endpointProtoField.String(data, 4)

			endpointEndpointStr, _ := endpointK8sKindField.String(data, 4)
			e.endpoint.Kind = types.EndpointKind(endpointEndpointStr)

			endpointK8sPodLabelsRaw, _ := endpointK8sLabelsField.String(data, 1024)
			endpointK8sLabelPairs := strings.Split(endpointK8sPodLabelsRaw, ",")
			for _, pair := range endpointK8sLabelPairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					continue
				}
				e.endpoint.PodLabels[kv[0]] = kv[1]
			}

			e.K8s.PodName, _ = k8sPodNameField.String(data, 128)
			e.K8s.Owner.Name, _ = k8sOwnerNameField.String(data, 128)
			e.K8s.HostNetwork, _ = k8sHostNetworkField.Bool(data)
			e.K8s.Namespace, _ = k8sNamespaceField.String(data, 128)
			for _, pair := range k8sLabelPairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					continue
				}
				e.K8s.PodLabels[kv[0]] = kv[1]
			}

			if e.K8s.HostNetwork {
				continue
			}

			// Kubernetes Network Policies can't block traffic from a pod's
			// own resident node. Therefore we must not generate a network
			// policy in that case.
			podIP, _ := k8sPodIPField.String(data, 15)
			if !e.egress && podIP == e.endpoint.Addr {
				continue
			}

			key := localPodKey(e)
			eventsBySource[key] = append(eventsBySource[key], e)
		}

		if len(eventsBySource) != 0 {
			// api.Warnf("Got %d events by source", len(eventsBySource))
			policies := handleEvents(eventsBySource)
			// api.Warnf("> Created %d policies", len(policies))
			policiesStr := FormatPolicies(policies)
			//// api.Warnf("> Policies:\n%s", policiesStr[:100])

			nd, _ := textds.NewPacketSingle()
			textField.SetString(api.Data(nd), policiesStr)
			textds.EmitAndRelease(api.Packet(nd))
		}

		return nil
	}, 9999)
	if err != nil {
		// api.Warnf("subscribing to syscalls: %s", err)
		return 1
	}
	return 0
}

func main() {}
