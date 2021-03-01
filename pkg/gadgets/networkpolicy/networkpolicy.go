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

package networkpolicy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"
	"strings"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/types"
)

var defaultLabelsToIgnore = map[string]struct{}{
	"controller-revision-hash": struct{}{},
	"pod-template-generation":  struct{}{},
	"pod-template-hash":        struct{}{},
}

type NetworkPolicyAdvisor struct {
	Events []types.KubernetesConnectionEvent

	LabelsToIgnore map[string]struct{}

	Policies []networkingv1.NetworkPolicy
}

func NewAdvisor() *NetworkPolicyAdvisor {
	return &NetworkPolicyAdvisor{
		LabelsToIgnore: defaultLabelsToIgnore,
	}
}

func (a *NetworkPolicyAdvisor) LoadFile(filename string) error {
	buf, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	return a.LoadBuffer(buf)
}

func (a *NetworkPolicyAdvisor) LoadBuffer(buf []byte) error {
	/* Try to read the file as an array */
	events := []types.KubernetesConnectionEvent{}
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
		event := types.KubernetesConnectionEvent{}
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 {
			continue
		}
		line++
		err = json.Unmarshal([]byte(text), &event)
		if err != nil {
			return fmt.Errorf("cannot parse line %d: %s", line, err)
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
func (a *NetworkPolicyAdvisor) localPodKey(e types.KubernetesConnectionEvent) (ret string) {
	return e.LocalPodNamespace + ":" + a.labelKeyString(e.LocalPodLabels)
}

func (a *NetworkPolicyAdvisor) networkPeerKey(e types.KubernetesConnectionEvent) (ret string) {
	if e.RemoteKind == "pod" {
		ret = e.RemoteKind + ":" + e.RemotePodNamespace + ":" + a.labelKeyString(e.RemotePodLabels)
	} else if e.RemoteKind == "svc" {
		ret = e.RemoteKind + ":" + e.RemoteSvcNamespace + ":" + a.labelKeyString(e.RemoteSvcLabelSelector)
	} else if e.RemoteKind == "other" {
		ret = e.RemoteKind + ":" + e.RemoteOther
	}
	return fmt.Sprintf("%s:%d", ret, e.Port)
}

func (a *NetworkPolicyAdvisor) eventToRule(e types.KubernetesConnectionEvent) (ports []networkingv1.NetworkPolicyPort, peers []networkingv1.NetworkPolicyPeer) {
	port := intstr.FromInt(int(e.Port))
	protocol := v1.Protocol("TCP")
	ports = []networkingv1.NetworkPolicyPort{
		networkingv1.NetworkPolicyPort{
			Port:     &port,
			Protocol: &protocol,
		},
	}
	if e.RemoteKind == "pod" {
		peers = []networkingv1.NetworkPolicyPeer{
			networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{MatchLabels: a.labelFilter(e.RemotePodLabels)},
			},
		}
		if e.LocalPodNamespace != e.RemotePodNamespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// TODO: the namespace might not have this "name" label
					"name": e.RemotePodNamespace,
				},
			}
		}
	} else if e.RemoteKind == "svc" {
		peers = []networkingv1.NetworkPolicyPeer{
			networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{MatchLabels: e.RemoteSvcLabelSelector},
			},
		}
		if e.LocalPodNamespace != e.RemoteSvcNamespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// TODO: the namespace might not have this "name" label
					"name": e.RemoteSvcNamespace,
				},
			}
		}
	} else if e.RemoteKind == "other" {
		peers = []networkingv1.NetworkPolicyPeer{
			networkingv1.NetworkPolicyPeer{
				IPBlock: &networkingv1.IPBlock{
					CIDR: e.RemoteOther + "/32",
				},
			},
		}
	} else {
		panic("unknown event")
	}
	return
}

func (a *NetworkPolicyAdvisor) GeneratePolicies() {
	eventsBySource := map[string][]types.KubernetesConnectionEvent{}
	for _, e := range a.Events {
		if e.Type != "connect" && e.Type != "accept" {
			continue
		}
		key := a.localPodKey(e)
		if _, ok := eventsBySource[key]; ok {
			eventsBySource[key] = append(eventsBySource[key], e)
		} else {
			eventsBySource[key] = []types.KubernetesConnectionEvent{e}
		}
	}

	for _, events := range eventsBySource {
		egressNetworkPeer := map[string]types.KubernetesConnectionEvent{}
		ingressNetworkPeer := map[string]types.KubernetesConnectionEvent{}
		for _, e := range events {
			key := a.networkPeerKey(e)
			if e.Type == "connect" {
				if _, ok := egressNetworkPeer[key]; ok {
					continue
				}

				egressNetworkPeer[key] = e
			} else if e.Type == "accept" {
				if _, ok := ingressNetworkPeer[key]; ok {
					continue
				}

				ingressNetworkPeer[key] = e
			}
		}
		egressPolicies := []networkingv1.NetworkPolicyEgressRule{}
		for _, p := range egressNetworkPeer {
			ports, peers := a.eventToRule(p)
			rule := networkingv1.NetworkPolicyEgressRule{
				Ports: ports,
				To:    peers,
			}
			egressPolicies = append(egressPolicies, rule)
		}
		ingressPolicies := []networkingv1.NetworkPolicyIngressRule{}
		for _, p := range ingressNetworkPeer {
			ports, peers := a.eventToRule(p)
			rule := networkingv1.NetworkPolicyIngressRule{
				Ports: ports,
				From:  peers,
			}
			ingressPolicies = append(ingressPolicies, rule)
		}

		name := events[0].LocalPodName
		if events[0].LocalPodOwner != "" {
			name = events[0].LocalPodOwner
		}
		name += "-network"
		policy := networkingv1.NetworkPolicy{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "networking.k8s.io/v1",
				Kind:       "NetworkPolicy",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: events[0].LocalPodNamespace,
				Labels:    map[string]string{},
			},
			Spec: networkingv1.NetworkPolicySpec{
				PodSelector: metav1.LabelSelector{MatchLabels: a.labelFilter(events[0].LocalPodLabels)},
				PolicyTypes: []networkingv1.PolicyType{"Ingress", "Egress"},
				Ingress:     ingressPolicies,
				Egress:      egressPolicies,
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
