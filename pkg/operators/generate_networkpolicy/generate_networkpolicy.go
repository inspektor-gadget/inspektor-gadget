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

package generate_networkpolicy

import (
	"errors"
	"fmt"
	"sort"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

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

func networkPeerKey(e NetworkEvent) (string, error) {
	var ret string
	switch e.endpoint.Kind {
	case types.EndpointKindPod:
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodLabels)
	case types.EndpointKindService:
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodLabels)
	case types.EndpointKindRaw:
		ret = string(e.endpoint.Kind) + ":" + e.endpoint.Addr
	default:
		return "", fmt.Errorf("unknown endpoint kind: %s", e.endpoint.Kind)
	}
	return fmt.Sprintf("%s:%d", ret, e.endpoint.Port), nil
}

func eventToRule(e NetworkEvent) ([]networkingv1.NetworkPolicyPort, []networkingv1.NetworkPolicyPeer, error) {
	port := intstr.FromInt(int(e.endpoint.Port))
	protocol := v1.Protocol(e.proto)
	ports := []networkingv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &protocol,
		},
	}
	var peers []networkingv1.NetworkPolicyPeer
	switch e.endpoint.Kind {
	case types.EndpointKindPod:
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
	case types.EndpointKindService:
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
	case types.EndpointKindRaw:
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
	default:
		return nil, nil, fmt.Errorf("unknown endpoint kind: %s", e.endpoint.Kind)
	}
	return ports, peers, nil
}

func sortIngressRules(rules []networkingv1.NetworkPolicyIngressRule) ([]networkingv1.NetworkPolicyIngressRule, error) {
	var errs []error
	sort.Slice(rules, func(i, j int) bool {
		ri, rj := rules[i], rules[j]

		// No need to support all network policies, but only the ones
		// generated by eventToRule()
		if len(ri.Ports) != 1 || len(rj.Ports) != 1 {
			errs = append(errs, fmt.Errorf("rules with multiple ports"))
			return true
		}
		if ri.Ports[0].Protocol == nil || rj.Ports[0].Protocol == nil {
			errs = append(errs, fmt.Errorf("rules without protocol"))
			return true
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
	return rules, errors.Join(errs...)
}

func sortEgressRules(rules []networkingv1.NetworkPolicyEgressRule) ([]networkingv1.NetworkPolicyEgressRule, error) {
	var errs []error
	sort.Slice(rules, func(i, j int) bool {
		ri, rj := rules[i], rules[j]

		// No need to support all network policies, but only the ones
		// generated by eventToRule()
		if len(ri.Ports) != 1 || len(rj.Ports) != 1 {
			errs = append(errs, fmt.Errorf("rules with multiple ports"))
			return true
		}
		if ri.Ports[0].Protocol == nil || rj.Ports[0].Protocol == nil {
			errs = append(errs, fmt.Errorf("rules without protocol"))
			return true
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
	return rules, errors.Join(errs...)
}

func handleEvents(eventsBySource map[string][]NetworkEvent) ([]networkingv1.NetworkPolicy, error) {
	policies := make([]networkingv1.NetworkPolicy, 0, len(eventsBySource))

	for _, events := range eventsBySource {
		egressNetworkPeer := map[string]NetworkEvent{}
		ingressNetworkPeer := map[string]NetworkEvent{}
		for _, e := range events {
			key, err := networkPeerKey(e)
			if err != nil {
				return nil, fmt.Errorf("generating network peer key: %w", err)
			}
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
			ports, peers, err := eventToRule(p)
			if err != nil {
				return nil, fmt.Errorf("generating network policy egress rule: %w", err)
			}
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
			ports, peers, err := eventToRule(p)
			if err != nil {
				return nil, fmt.Errorf("generating network policy ingress rule: %w", err)
			}
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
		ingressRules, err := sortIngressRules(ingressPolicies)
		if err != nil {
			return nil, fmt.Errorf("sorting ingress rules: %w", err)
		}
		egressRules, err := sortEgressRules(egressPolicies)
		if err != nil {
			return nil, fmt.Errorf("sorting egress rules: %w", err)
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
				Ingress:     ingressRules,
				Egress:      egressRules,
			},
		}
		policies = append(policies, policy)
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	return policies, nil
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
