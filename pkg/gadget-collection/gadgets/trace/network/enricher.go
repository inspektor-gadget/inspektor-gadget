// Copyright 2019-2022 The Inspektor Gadget authors
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

package networkgraph

import (
	"context"
	"strings"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	nettracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Enricher struct {
	withKubernetes bool
	clientset      *kubernetes.Clientset
	node           string
}

func NewEnricher(withKubernetes bool, node string) (*Enricher, error) {
	if !withKubernetes {
		return &Enricher{
			withKubernetes: withKubernetes,
			node:           node,
		}, nil
	}

	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, err
	}
	return &Enricher{
		withKubernetes: withKubernetes,
		clientset:      clientset,
		node:           node,
	}, nil
}

func (e *Enricher) convertEvent(
	edge nettracer.Edge,
	pods *corev1.PodList,
	svcs *corev1.ServiceList,
) types.Event {
	var namespace, name string
	parts := strings.Split(edge.Key, "/")
	if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	}

	out := types.Event{
		Event: eventtypes.Event{
			Type: eventtypes.NORMAL,
			CommonData: eventtypes.CommonData{
				Node:      e.node,
				Namespace: namespace,
				Pod:       name,
			},
			Message: "",
		},

		PktType: edge.PktType,
		Proto:   edge.Proto,
		Port:    edge.Port,

		RemoteAddr: edge.Addr.String(),
	}

	// Find the pod resource where the packet capture occurred
	localPodIndex := -1
	for i, pod := range pods.Items {
		if pod.GetNamespace() == namespace && pod.GetName() == name {
			localPodIndex = i
			out.PodLabels = pod.Labels
			// Kubernetes Network Policies can't block traffic from
			// a pod's resident node. Therefore we must not
			// generate a network policy in that case. The advisor
			// will use PodHostIP to detect this.
			out.PodHostIP = pod.Status.HostIP
			out.PodIP = pod.Status.PodIP
			break
		}
	}

	// Find the remote pod, if any
	for _, pod := range pods.Items {
		if pod.Spec.HostNetwork {
			continue
		}
		if pod.Status.PodIP == edge.Addr.String() {
			out.RemoteKind = types.RemoteKindPod
			out.RemoteNamespace = pod.Namespace
			out.RemoteName = pod.Name
			out.RemoteLabels = pod.Labels
			break
		}
	}
	if localPodIndex == -1 {
		return out
	}

	// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
	// shorter name without the random suffix. That will be used to
	// generate the network policy name.
	if pods.Items[localPodIndex].OwnerReferences != nil {
		nameItems := strings.Split(out.Pod, "-")
		if len(nameItems) > 2 {
			out.PodOwner = strings.Join(nameItems[:len(nameItems)-2], "-")
		}
	}

	if out.RemoteKind == "" {
		for _, svc := range svcs.Items {
			if svc.Spec.ClusterIP == edge.Addr.String() {
				out.RemoteKind = types.RemoteKindService
				out.RemoteNamespace = svc.Namespace
				out.RemoteName = svc.Name
				out.RemoteLabels = svc.Spec.Selector
				break
			}
		}
	}

	if out.RemoteKind == "" {
		out.RemoteKind = types.RemoteKindOther
	}

	return out
}

func (e *Enricher) Enrich(edges []nettracer.Edge) (out []types.Event) {
	var err error
	pods := &corev1.PodList{}
	svcs := &corev1.ServiceList{}

	if e.withKubernetes {
		pods, err = e.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("%s", err)
			return
		}
		svcs, err = e.clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			log.Errorf("%s", err)
			return
		}
	}

	for _, edge := range edges {
		out = append(out, e.convertEvent(edge, pods, svcs))
	}
	return out
}

func (e *Enricher) Close() {
}
