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

package tool

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	k8syaml "sigs.k8s.io/yaml"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var (
	inputFileName  string
	outputFileName string
)

func newAdivseNetworkPolidyCmd() *cobra.Command {
	networkPolicyCmd := &cobra.Command{
		Use:   "report-network-policy",
		Short: "Generate network policies based on recorded network activity",
		RunE:  runNetworkPolicyReport,
	}

	networkPolicyCmd.PersistentFlags().StringVarP(&inputFileName, "input", "", "", "File with recorded network activity")
	networkPolicyCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")

	return networkPolicyCmd
}

func runNetworkPolicyReport(cmd *cobra.Command, args []string) error {
	if inputFileName == "" {
		return commonutils.WrapInErrMissingArgs("--input")
	}

	buf, err := os.ReadFile(inputFileName)
	if err != nil {
		return err
	}

	events, err := LoadBuffer(buf)
	if err != nil {
		return err
	}

	eventsBySource := map[string][]NetworkEvent{}
	for _, e := range events {
		if e.K8s.HostNetwork {
			continue
		}

		// Kubernetes Network Policies can't block traffic from a pod's
		// own resident node. Therefore we must not generate a network
		// policy in that case.
		if e.Egress == 0 && e.K8s.PodIp == e.Endpoint.Addr {
			continue
		}

		k8sLabelPairs := strings.Split(e.K8s.PodLabelsRaw, ",")
		e.K8s.PodLabels = map[string]string{}
		for _, pair := range k8sLabelPairs {
			kv := strings.Split(pair, "=")
			if len(kv) != 2 {
				continue
			}
			e.K8s.PodLabels[kv[0]] = kv[1]
		}

		k8sLabelPairs = strings.Split(e.Endpoint.K8s.PodLabelsRaw, ",")
		e.Endpoint.K8s.PodLabels = map[string]string{}
		for _, pair := range k8sLabelPairs {
			kv := strings.Split(pair, "=")
			if len(kv) != 2 {
				continue
			}
			e.Endpoint.K8s.PodLabels[kv[0]] = kv[1]
		}

		// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
		// shorter name without the random suffix. That will be used to
		// generate the network policy name.
		if e.K8s.Owner.Name != "" {
			numDashes := 0
			lastIndex := len(e.K8s.PodName) - 1
			for ; lastIndex >= 0; lastIndex-- {
				if e.K8s.PodName[lastIndex] != '-' {
					continue
				}

				numDashes++
				if numDashes == 2 {
					break
				}
			}

			if numDashes == 2 {
				e.K8s.Owner.Name = e.K8s.PodName[:lastIndex]
			}
		}

		key := localPodKey(e)
		eventsBySource[key] = append(eventsBySource[key], e)
	}

	policiesStr := ""
	if len(eventsBySource) != 0 {
		policies := handleEvents(eventsBySource)
		policiesStr = formatPolicies(policies)
	}

	w, closure, err := newWriter(outputFileName)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", outputFileName, err)
	}
	defer closure()

	_, err = w.Write([]byte(policiesStr))
	if err != nil {
		return fmt.Errorf("writing file %q: %w", outputFileName, err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("flushing file %q: %w", outputFileName, err)
	}

	return nil
}

func LoadBuffer(buf []byte) ([]NetworkEvent, error) {
	/* Try to read the file as an array */
	events := []NetworkEvent{}
	err := json.Unmarshal(buf, &events)
	if err == nil {
		return events, nil
	}

	/* If it fails, read by line */
	events = nil
	line := 0
	scanner := bufio.NewScanner(bytes.NewReader(buf))
	for scanner.Scan() {
		event := NetworkEvent{}
		text := strings.TrimSpace(scanner.Text())
		if len(text) == 0 {
			continue
		}
		line++
		err = json.Unmarshal([]byte(text), &event)
		if err != nil {
			return nil, fmt.Errorf("parsing line %d: %w", line, err)
		}
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return events, nil
}

type EndpointK8sData struct {
	Kind         types.EndpointKind `json:"kind"`
	PodLabels    map[string]string
	PodLabelsRaw string `json:"labels"`
	Namespace    string `json:"namespace"`
	Name         string `json:"podname"`
}

type L4Endpoint struct {
	Addr    string `json:"addr"`
	Version uint8  `json:"version"`

	K8s   EndpointK8sData `json:"k8s"`
	Port  uint16          `json:"port"`
	Proto string          `json:"proto"`
}

// K8sMetadata is a modified copy of types.K8sMetadata.
// types.K8sMetadata has the json tag `json:"podLabels"`.
// The formatter transformed this to a single string for JSON
type K8sMetadata struct {
	Namespace    string `json:"namespace"`
	PodName      string `json:"podName"`
	PodLabelsRaw string `json:"podLabels"`
	PodLabels    map[string]string

	HostNetwork bool                    `json:"hostNetwork"`
	Owner       types.K8sOwnerReference `json:"owner"`
	PodIp       string                  `json:"podIP"`
	HostIp      string                  `json:"hostIP"`
}

type NetworkEvent struct {
	Egress   int         `json:"egress"`
	Endpoint L4Endpoint  `json:"endpoint"`
	K8s      K8sMetadata `json:"k8s"`
}

func newWriter(outputFileName string) (*bufio.Writer, func(), error) {
	var w *bufio.Writer
	var closure func()
	if outputFileName == "-" {
		w = bufio.NewWriter(os.Stdout)
		closure = func() {}
	} else {
		outputFile, err := os.Create(outputFileName)
		if err != nil {
			return nil, nil, err
		}
		closure = func() { outputFile.Close() }
		w = bufio.NewWriter(outputFile)
	}

	return w, closure, nil
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
	if e.Endpoint.K8s.Kind == types.EndpointKindPod {
		ret = string(e.Endpoint.K8s.Kind) + ":" + e.Endpoint.K8s.Namespace + ":" + labelKeyString(e.Endpoint.K8s.PodLabels)
	} else if e.Endpoint.K8s.Kind == types.EndpointKindService {
		ret = string(e.Endpoint.K8s.Kind) + ":" + e.Endpoint.K8s.Namespace + ":" + labelKeyString(e.Endpoint.K8s.PodLabels)
	} else if e.Endpoint.K8s.Kind == types.EndpointKindRaw {
		ret = string(e.Endpoint.K8s.Kind) + ":" + e.Endpoint.Addr
	} else {
		return "", fmt.Errorf("unknown endpoint kind: %s", e.Endpoint.K8s.Kind)
	}
	return fmt.Sprintf("%s:%d", ret, e.Endpoint.Port), nil
}

func eventToRule(e NetworkEvent) (ports []networkingv1.NetworkPolicyPort, peers []networkingv1.NetworkPolicyPeer, err error) {
	port := intstr.FromInt(int(e.Endpoint.Port))
	protocol := v1.Protocol(e.Endpoint.Proto)
	ports = []networkingv1.NetworkPolicyPort{
		{
			Port:     &port,
			Protocol: &protocol,
		},
	}
	if e.Endpoint.K8s.Kind == types.EndpointKindPod {
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: labelFilter(e.Endpoint.K8s.PodLabels)},
			},
		}
		if e.K8s.Namespace != e.Endpoint.K8s.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.Endpoint.K8s.Namespace,
				},
			}
		}
	} else if e.Endpoint.K8s.Kind == types.EndpointKindService {
		peers = []networkingv1.NetworkPolicyPeer{
			{
				PodSelector: &metav1.LabelSelector{MatchLabels: e.Endpoint.K8s.PodLabels},
			},
		}
		if e.K8s.Namespace != e.Endpoint.K8s.Namespace {
			peers[0].NamespaceSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					// Kubernetes 1.22 is guaranteed to add the following label on namespaces:
					// kubernetes.io/metadata.name=obj.Name
					// See:
					// https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/2161-apiserver-default-labels#proposal
					"kubernetes.io/metadata.name": e.Endpoint.K8s.Namespace,
				},
			}
		}
	} else if e.Endpoint.K8s.Kind == types.EndpointKindRaw {
		if e.Endpoint.Addr == "127.0.0.1" {
			// No need to generate a network policy for localhost
			peers = []networkingv1.NetworkPolicyPeer{}
		} else {
			peers = []networkingv1.NetworkPolicyPeer{
				{
					IPBlock: &networkingv1.IPBlock{
						CIDR: e.Endpoint.Addr + "/32",
					},
				},
			}
		}
	} else {
		err = fmt.Errorf("unknown endpoint kind: %s", e.Endpoint.K8s.Kind)
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
			key, err := networkPeerKey(e)
			if err != nil {
				fmt.Printf("getting network peer key: %s\n", err)
				continue
			}
			// api.Warnf("key for event with kind %s: %s", e.Endpoint.K8s.Kind, key)
			if e.Egress == 1 {
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
				fmt.Printf("getting egress rule: %s\n", err)
				continue
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
				fmt.Printf("getting ingress rule: %s\n", err)
				continue
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

func formatPolicies(policies []networkingv1.NetworkPolicy) (out string) {
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
