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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
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

func enrich(event *types.Event, node string, pods *corev1.PodList, svcs *corev1.ServiceList) {
	var namespace, name string
	parts := strings.Split(event.Key, "/")
	if len(parts) == 2 {
		namespace = parts[0]
		name = parts[1]
	}
	event.Node = node
	event.Namespace = namespace
	event.Pod = name

	// Find the pod resource where the packet capture occurred
	localPodIndex := -1
	for i, pod := range pods.Items {
		if pod.GetNamespace() == namespace && pod.GetName() == name {
			localPodIndex = i
			event.PodLabels = pod.Labels
			// Kubernetes Network Policies can't block traffic from
			// a pod's resident node. Therefore we must not
			// generate a network policy in that case. The advisor
			// will use PodHostIP to detect this.
			event.PodHostIP = pod.Status.HostIP
			event.PodIP = pod.Status.PodIP
			break
		}
	}

	// Find the remote pod, if any
	for _, pod := range pods.Items {
		if pod.Spec.HostNetwork {
			continue
		}
		if pod.Status.PodIP == event.RemoteAddr {
			event.RemoteKind = types.RemoteKindPod
			event.RemoteNamespace = pod.Namespace
			event.RemoteName = pod.Name
			event.RemoteLabels = pod.Labels
			break
		}
	}
	if localPodIndex == -1 {
		return
	}

	// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
	// shorter name without the random suffix. That will be used to
	// generate the network policy name.
	if pods.Items[localPodIndex].OwnerReferences != nil {
		nameItems := strings.Split(event.Pod, "-")
		if len(nameItems) > 2 {
			event.PodOwner = strings.Join(nameItems[:len(nameItems)-2], "-")
		}
	}

	if event.RemoteKind == "" {
		for _, svc := range svcs.Items {
			if svc.Spec.ClusterIP == event.RemoteAddr {
				event.RemoteKind = types.RemoteKindService
				event.RemoteNamespace = svc.Namespace
				event.RemoteName = svc.Name
				event.RemoteLabels = svc.Spec.Selector
				break
			}
		}
	}

	if event.RemoteKind == "" {
		event.RemoteKind = types.RemoteKindOther
	}
}

func (e *Enricher) Enrich(events []*types.Event) {
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

	for _, event := range events {
		enrich(event, e.node, pods, svcs)
	}
}

func (e *Enricher) Close() {
}
