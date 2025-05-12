// Copyright 2019-2021 The Inspektor Gadget authors
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

package advisor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var defaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": {},
	"pod-template-generation":  {},
	"pod-template-hash":        {},
}

type NetworkPolicyAdvisor struct {
	Events []types.Event

	LabelsToIgnore map[string]struct{}

	Policies []networkingv1.NetworkPolicy
}

func NewAdvisor() *NetworkPolicyAdvisor {
	return &NetworkPolicyAdvisor{
		LabelsToIgnore: defaultLabelsToIgnore,
	}
}

func (a *NetworkPolicyAdvisor) LoadFile(filename string) error {
	buf, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return a.LoadBuffer(buf)
}

func (a *NetworkPolicyAdvisor) LoadBuffer(buf []byte) error {
	/* Try to read the file as an array */
	events := []types.Event{}
	err := json.Unmarshal(buf, &events)
	if err == nil {
		a.Events = events
		return nil
	}

	/* If it fails, read by line */
	events = nil
	line := 0
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	for scanner.Scan() {
		event := types.Event{}
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 {
			continue
		}
		line++
		err = json.Unmarshal([]byte(text), &event)
		if err != nil {
			return fmt.Errorf("parsing line %d: %w", line, err)
		}
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	a.Events = events

	return nil
}

/* labelFilteredKeyList returns a sorted list of label keys but without the labels to
 * ignore.
 */
func (a *NetworkPolicyAdvisor) labelFilteredKeyList(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		if _, ok := a.LabelsToIgnore[k]; ok {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	return keys
}

func (a *NetworkPolicyAdvisor) labelFilter(labels map[string]string) map[string]string {
	ret := map[string]string{}
	for k := range labels {
		if _, ok := a.LabelsToIgnore[k]; ok {
			continue
		}
		ret[k] = labels[k]
	}
	return ret
}

/* labelKeyString returns a sorted list of labels in a single string.
 * label1=value1,label2=value2
 */
func (a *NetworkPolicyAdvisor) labelKeyString(labels map[string]string) (ret string) {
	keys := a.labelFilteredKeyList(labels)

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
func (a *NetworkPolicyAdvisor) localPodKey(e types.Event) (ret string) {
	return e.K8s.Namespace + ":" + a.labelKeyString(e.PodLabels)
}

func (a *NetworkPolicyAdvisor) networkPeerKey(e types.Event) (ret string) {
	switch e.DstEndpoint.Kind {
	case eventtypes.EndpointKindPod:
		ret = string(e.DstEndpoint.Kind) + ":" + e.DstEndpoint.Namespace + ":" + a.labelKeyString(e.DstEndpoint.PodLabels)
	case eventtypes.EndpointKindService:
		ret = string(e.DstEndpoint.Kind) + ":" + e.DstEndpoint.Namespace + ":" + a.labelKeyString(e.DstEndpoint.PodLabels)
	case eventtypes.EndpointKindRaw:
		ret = string(e.DstEndpoint.Kind) + ":" + e.DstEndpoint.Addr
	}
	return fmt.Sprintf("%s:%d", ret, e.Port)
}

func (a *NetworkPolicyAdvisor) eventToRule(e types.Event) (ports []networkingv1.NetworkPolicyPort, peers []networkingv1.NetworkPolicyPeer) {
	port := intstr.FromInt(int(e.Port))
	protocol := v1.Protocol(strings.ToUpper(e.Proto))
	ports = []networkingv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &protocol,
		},
	}
	switch e.DstEndpoint.Kind {
	case eventtypes.EndpointKindPod:
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: a.labelFilter(e.DstEndpoint.PodLabels)},
			},
		}
		if e.K8s.Namespace != e.DstEndpoint.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.DstEndpoint.Namespace,
				},
			}
		}
	case eventtypes.EndpointKindService:
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: e.DstEndpoint.PodLabels},
			},
		}
		if e.K8s.Namespace != e.DstEndpoint.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.DstEndpoint.Namespace,
				},
			}
		}
	case eventtypes.EndpointKindRaw:
		if e.DstEndpoint.Addr == "127.0.0.1" {
			// No need to generate a network policy for localhost
			peers = []networkingv1.NetworkPolicyPeer{}
		} else {
			peers = []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: e.DstEndpoint.Addr + "/32",
					},
				},
			}
		}
	default:
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

func (a *NetworkPolicyAdvisor) GeneratePolicies() {
	eventsBySource := map[string][]types.Event{}
	for _, e := range a.Events {
		if e.Type != eventtypes.NORMAL {
			continue
		}
		if e.PktType != "HOST" && e.PktType != "OUTGOING" {
			continue
		}
		// ignore events on the host netns
		if e.K8s.HostNetwork {
			continue
		}

		// Kubernetes Network Policies can't block traffic from a pod's
		// own resident node. Therefore we must not generate a network
		// policy in that case.
		if e.PktType == "HOST" && e.PodHostIP == e.DstEndpoint.Addr {
			continue
		}

		key := a.localPodKey(e)
		eventsBySource[key] = append(eventsBySource[key], e)
	}

	for _, events := range eventsBySource {
		egressNetworkPeer := map[string]types.Event{}
		ingressNetworkPeer := map[string]types.Event{}
		for _, e := range events {
			key := a.networkPeerKey(e)
			if e.PktType == "OUTGOING" {
				if _, ok := egressNetworkPeer[key]; ok {
					continue
				}

				egressNetworkPeer[key] = e
			} else if e.PktType == "HOST" {
				if _, ok := ingressNetworkPeer[key]; ok {
					continue
				}

				ingressNetworkPeer[key] = e
			}
		}
		egressPolicies := []networkingv1.NetworkPolicyEgressRule{}
		for _, p := range egressNetworkPeer {
			ports, peers := a.eventToRule(p)
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
			ports, peers := a.eventToRule(p)
			if len(peers) > 0 {
				rule := networkingv1.NetworkPolicyIngressRule{
					Ports: ports,
					From:  peers,
				}
				ingressPolicies = append(ingressPolicies, rule)
			}
		}

		name := events[0].K8s.PodName
		if events[0].PodOwner != "" {
			name = events[0].PodOwner
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
				PodSelector: metav1.LabelSelector{MatchLabels: a.labelFilter(events[0].PodLabels)},
				PolicyTypes: []networkingv1.PolicyType{"Ingress", "Egress"},
				Ingress:     sortIngressRules(ingressPolicies),
				Egress:      sortEgressRules(egressPolicies),
			},
		}
		a.Policies = append(a.Policies, policy)
	}

	sort.Slice(a.Policies, func(i, j int) bool {
		return a.Policies[i].Name < a.Policies[j].Name
	})
}

func (a *NetworkPolicyAdvisor) FormatPolicies() (out string) {
	for i, p := range a.Policies {
		yamlOutput, err := k8syaml.Marshal(p)
		if err != nil {
			continue
		}
		sep := "---\n"
		if i == len(a.Policies)-1 {
			sep = ""
		}
		out += fmt.Sprintf("%s%s", string(yamlOutput), sep)
	}
	return
}
