// Copyright 2026 The Inspektor Gadget authors
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
	"fmt"
	"sort"
	"strconv"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// CiliumNetworkPolicy is a minimal representation of the CiliumNetworkPolicy CRD (cilium.io/v2).
// Defined locally to avoid importing the full Cilium dependency tree.
// See the upstream types at:
// https://github.com/cilium/cilium/blob/main/pkg/k8s/apis/cilium.io/v2/cnp_types.go
type CiliumNetworkPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              *CiliumNetworkPolicySpec `json:"spec,omitempty"`
}

type CiliumNetworkPolicySpec struct {
	EndpointSelector metav1.LabelSelector `json:"endpointSelector"`
	Ingress          []CiliumIngressRule  `json:"ingress,omitempty"`
	Egress           []CiliumEgressRule   `json:"egress,omitempty"`
}

type CiliumIngressRule struct {
	FromEndpoints []metav1.LabelSelector `json:"fromEndpoints,omitempty"`
	FromCIDR      []string               `json:"fromCIDR,omitempty"`
	ToPorts       []CiliumPortRule       `json:"toPorts,omitempty"`
}

type CiliumEgressRule struct {
	ToEndpoints []metav1.LabelSelector `json:"toEndpoints,omitempty"`
	ToCIDR      []string               `json:"toCIDR,omitempty"`
	ToPorts     []CiliumPortRule       `json:"toPorts,omitempty"`
}

// CiliumPortRule groups ports for a single rule. Cilium uses string port values.
type CiliumPortRule struct {
	Ports []CiliumPortProtocol `json:"ports"`
}

type CiliumPortProtocol struct {
	Port     string `json:"port"`
	Protocol string `json:"protocol,omitempty"`
}

// ciliumPeerKey identifies a unique endpoint peer without the port, so that events
// sharing the same peer but different ports can be grouped into a single Cilium rule.
func ciliumPeerKey(e NetworkEvent) (string, error) {
	switch e.endpoint.Kind {
	case types.EndpointKindPod:
		return string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodLabels), nil
	case types.EndpointKindService:
		return string(e.endpoint.Kind) + ":" + e.endpoint.Namespace + ":" + labelKeyString(e.endpoint.PodSelector), nil
	case types.EndpointKindRaw:
		return string(e.endpoint.Kind) + ":" + e.endpoint.Addr, nil
	default:
		return "", fmt.Errorf("unknown endpoint kind: %s", e.endpoint.Kind)
	}
}

// ciliumEndpointSelector builds the LabelSelector for a Cilium endpoint peer.
// For cross-namespace peers, the target namespace is embedded via the standard
// io.kubernetes.pod.namespace label that Cilium maps from Kubernetes identity labels.
func ciliumEndpointSelector(e NetworkEvent, localNamespace string) (metav1.LabelSelector, error) {
	var base map[string]string
	switch e.endpoint.Kind {
	case types.EndpointKindPod:
		base = labelFilter(e.endpoint.PodLabels)
	case types.EndpointKindService:
		base = e.endpoint.PodSelector
	default:
		return metav1.LabelSelector{}, fmt.Errorf("endpointSelector called for non-pod kind: %s", e.endpoint.Kind)
	}

	sel := make(map[string]string, len(base)+1)
	for k, v := range base {
		sel[k] = v
	}

	// Cilium resolves namespace membership via the io.kubernetes.pod.namespace identity
	// label; unlike K8s NetworkPolicy there is no separate namespaceSelector field.
	if e.endpoint.Namespace != "" && e.endpoint.Namespace != localNamespace {
		sel["io.kubernetes.pod.namespace"] = e.endpoint.Namespace
	}

	return metav1.LabelSelector{MatchLabels: sel}, nil
}

// peerGroup collects all NetworkEvents that share the same peer endpoint (same
// labels/address, different ports). Ports are aggregated into a single Cilium rule.
type peerGroup struct {
	events []NetworkEvent
}

// handleCiliumEvents converts observed network events into CiliumNetworkPolicy objects.
// Compared to the K8s NetworkPolicy output, this groups all ports for the same peer
// into a single rule, which produces shorter and easier-to-read policies.
func handleCiliumEvents(eventsBySource map[string][]NetworkEvent) ([]CiliumNetworkPolicy, error) {
	policies := make([]CiliumNetworkPolicy, 0, len(eventsBySource))

	for _, events := range eventsBySource {
		if len(events) == 0 {
			continue
		}

		egressByPeer := map[string]*peerGroup{}
		ingressByPeer := map[string]*peerGroup{}

		for _, e := range events {
			key, err := ciliumPeerKey(e)
			if err != nil {
				return nil, fmt.Errorf("computing cilium peer key: %w", err)
			}
			if e.egress {
				if _, ok := egressByPeer[key]; !ok {
					egressByPeer[key] = &peerGroup{}
				}
				egressByPeer[key].events = append(egressByPeer[key].events, e)
			} else {
				if _, ok := ingressByPeer[key]; !ok {
					ingressByPeer[key] = &peerGroup{}
				}
				ingressByPeer[key].events = append(ingressByPeer[key].events, e)
			}
		}

		localNamespace := events[0].K8s.Namespace

		ingressRules, err := buildCiliumIngressRules(ingressByPeer, localNamespace)
		if err != nil {
			return nil, fmt.Errorf("building cilium ingress rules: %w", err)
		}
		egressRules, err := buildCiliumEgressRules(egressByPeer, localNamespace)
		if err != nil {
			return nil, fmt.Errorf("building cilium egress rules: %w", err)
		}

		sortCiliumIngressRules(ingressRules)
		sortCiliumEgressRules(egressRules)

		name := events[0].K8s.PodName
		if events[0].K8s.Owner.Name != "" {
			name = events[0].K8s.Owner.Name
		}
		name += "-network"

		policy := CiliumNetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "cilium.io/v2",
				Kind:       "CiliumNetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: localNamespace,
			},
			Spec: &CiliumNetworkPolicySpec{
				EndpointSelector: metav1.LabelSelector{
					MatchLabels: labelFilter(events[0].K8s.PodLabels),
				},
				Ingress: ingressRules,
				Egress:  egressRules,
			},
		}
		policies = append(policies, policy)
	}

	sort.Slice(policies, func(i, j int) bool {
		return policies[i].Name < policies[j].Name
	})

	return policies, nil
}

func buildCiliumIngressRules(byPeer map[string]*peerGroup, localNamespace string) ([]CiliumIngressRule, error) {
	rules := make([]CiliumIngressRule, 0, len(byPeer))
	for _, pg := range byPeer {
		e0 := pg.events[0]
		ports := aggregateCiliumPorts(pg.events)

		switch e0.endpoint.Kind {
		case types.EndpointKindPod, types.EndpointKindService:
			sel, err := ciliumEndpointSelector(e0, localNamespace)
			if err != nil {
				return nil, err
			}
			rules = append(rules, CiliumIngressRule{
				FromEndpoints: []metav1.LabelSelector{sel},
				ToPorts:       ports,
			})
		case types.EndpointKindRaw:
			if e0.endpoint.Addr == "127.0.0.1" {
				continue
			}
			rules = append(rules, CiliumIngressRule{
				FromCIDR: []string{e0.endpoint.Addr + "/32"},
				ToPorts:  ports,
			})
		default:
			return nil, fmt.Errorf("unknown endpoint kind: %s", e0.endpoint.Kind)
		}
	}
	return rules, nil
}

func buildCiliumEgressRules(byPeer map[string]*peerGroup, localNamespace string) ([]CiliumEgressRule, error) {
	rules := make([]CiliumEgressRule, 0, len(byPeer))
	for _, pg := range byPeer {
		e0 := pg.events[0]
		ports := aggregateCiliumPorts(pg.events)

		switch e0.endpoint.Kind {
		case types.EndpointKindPod, types.EndpointKindService:
			sel, err := ciliumEndpointSelector(e0, localNamespace)
			if err != nil {
				return nil, err
			}
			rules = append(rules, CiliumEgressRule{
				ToEndpoints: []metav1.LabelSelector{sel},
				ToPorts:     ports,
			})
		case types.EndpointKindRaw:
			if e0.endpoint.Addr == "127.0.0.1" {
				continue
			}
			rules = append(rules, CiliumEgressRule{
				ToCIDR:  []string{e0.endpoint.Addr + "/32"},
				ToPorts: ports,
			})
		default:
			return nil, fmt.Errorf("unknown endpoint kind: %s", e0.endpoint.Kind)
		}
	}
	return rules, nil
}

// aggregateCiliumPorts deduplicates and sorts all port+protocol pairs from a peer group.
func aggregateCiliumPorts(events []NetworkEvent) []CiliumPortRule {
	seen := map[string]struct{}{}
	ports := []CiliumPortProtocol{}

	for _, e := range events {
		key := strconv.Itoa(int(e.endpoint.Port)) + "/" + e.proto
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ports = append(ports, CiliumPortProtocol{
			Port:     strconv.Itoa(int(e.endpoint.Port)),
			Protocol: e.proto,
		})
	}

	if len(ports) == 0 {
		return nil
	}

	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Protocol != ports[j].Protocol {
			return ports[i].Protocol < ports[j].Protocol
		}
		pi, ei := strconv.Atoi(ports[i].Port)
		pj, ej := strconv.Atoi(ports[j].Port)
		if ei == nil && ej == nil {
			return pi < pj
		}
		return ports[i].Port < ports[j].Port
	})

	return []CiliumPortRule{{Ports: ports}}
}

func sortCiliumIngressRules(rules []CiliumIngressRule) {
	sort.Slice(rules, func(i, j int) bool {
		yi, _ := k8syaml.Marshal(rules[i])
		yj, _ := k8syaml.Marshal(rules[j])
		return string(yi) < string(yj)
	})
}

func sortCiliumEgressRules(rules []CiliumEgressRule) {
	sort.Slice(rules, func(i, j int) bool {
		yi, _ := k8syaml.Marshal(rules[i])
		yj, _ := k8syaml.Marshal(rules[j])
		return string(yi) < string(yj)
	})
}

// FormatCiliumPolicies serializes a list of CiliumNetworkPolicy objects to YAML,
// separated by "---" document markers.
func FormatCiliumPolicies(policies []CiliumNetworkPolicy) (out string) {
	for i, p := range policies {
		yamlOutput, err := k8syaml.Marshal(p)
		if err != nil {
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
