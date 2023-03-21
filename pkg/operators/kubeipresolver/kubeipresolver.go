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
// up IP addresses in Kubernetes resources such as pods and services. It is
// currently only used by the 'trace network' gadget.
package kubeipresolver

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	OperatorName = "KubeIPResolver"
)

// KubeNetworkInformation is for now a specific interface for `trace network` gadget
// TODO: More granular and "shareable" interfaces
type KubeNetworkInformation interface {
	// Local/Host
	SetPodOwner(string)
	SetPodHostIP(string)
	SetPodIP(string)
	SetPodLabels(map[string]string)

	// Remote
	GetRemoteIP() string
	SetRemoteName(string)
	SetRemoteNamespace(string)
	SetRemoteKind(types.RemoteKind)
	SetRemotePodLabels(map[string]string)
}

type KubeIPResolver struct {
	clientset *kubernetes.Clientset
}

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
	return []string{kubemanager.OperatorName}
}

func (k *KubeIPResolver) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	km := kubemanager.KubeManager{}
	if !km.CanOperateOn(gadget) {
		return false
	}

	_, hasNetworkInf := gadget.EventPrototype().(KubeNetworkInformation)
	return hasNetworkInf
}

func (k *KubeIPResolver) Init(params *params.Params) error {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return fmt.Errorf("creating new k8s clientset: %w", err)
	}
	k.clientset = clientset
	return nil
}

func (k *KubeIPResolver) Close() error {
	return nil
}

func (k *KubeIPResolver) Instantiate(gadgetCtx operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	return &KubeIPResolverInstance{
		gadgetCtx:      gadgetCtx,
		manager:        k,
		gadgetInstance: gadgetInstance,
	}, nil
}

type KubeIPResolverInstance struct {
	gadgetCtx      operators.GadgetContext
	manager        *KubeIPResolver
	gadgetInstance any
}

func (m *KubeIPResolverInstance) Name() string {
	return "KubeNetworkManagerInstance"
}

func (m *KubeIPResolverInstance) PreGadgetRun() error {
	return nil
}

func (m *KubeIPResolverInstance) PostGadgetRun() error {
	return nil
}

func (m *KubeIPResolverInstance) enrich(ev any) {
	additionalInfo, _ := ev.(KubeNetworkInformation)
	containerInfo, _ := ev.(operators.ContainerInfoGetters)

	// TODO: Cache these kind of stuff for some seconds?
	// Pods("").Watch does not work, since pod.Status is not updated live
	// 			-> Old IPs
	pods, err := m.manager.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing pods: %v", err)
		return
	}

	additionalInfo.SetRemoteKind(types.RemoteKindOther)

	foundLocal := false
	foundRemote := false
	remoteIP := additionalInfo.GetRemoteIP()

	for i, pod := range pods.Items {
		if foundLocal && foundRemote {
			return
		}

		if pod.Namespace == containerInfo.GetNamespace() && pod.Name == containerInfo.GetPod() {
			foundLocal = true
			additionalInfo.SetPodIP(pod.Status.PodIP)
			additionalInfo.SetPodHostIP(pod.Status.HostIP)
			additionalInfo.SetPodLabels(pod.Labels)

			// When the pod belongs to Deployment, ReplicaSet or DaemonSet, find the
			// shorter name without the random suffix. That will be used to
			// generate the network policy name.
			if pods.Items[i].OwnerReferences != nil {
				nameItems := strings.Split(pods.Items[i].Name, "-")
				if len(nameItems) > 2 {
					additionalInfo.SetPodOwner(strings.Join(nameItems[:len(nameItems)-2], "-"))
				}
			}
		}

		if pod.Spec.HostNetwork {
			continue
		}
		if pod.Status.PodIP == remoteIP {
			foundRemote = true
			additionalInfo.SetRemoteKind(types.RemoteKindPod)
			additionalInfo.SetRemoteName(pod.Name)
			additionalInfo.SetRemoteNamespace(pod.Namespace)
			additionalInfo.SetRemotePodLabels(pod.Labels)
		}
	}

	if foundRemote {
		return
	}

	svcs, err := m.manager.clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing services: %s", err)
		return
	}

	for _, svc := range svcs.Items {
		if svc.Spec.ClusterIP == remoteIP {
			additionalInfo.SetRemoteKind(types.RemoteKindService)
			additionalInfo.SetRemoteName(svc.Name)
			additionalInfo.SetRemoteNamespace(svc.Namespace)
			additionalInfo.SetRemotePodLabels(svc.Labels)
			break
		}
	}
}

func (m *KubeIPResolverInstance) EnrichEvent(ev any) error {
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeIPResolver{})
}
