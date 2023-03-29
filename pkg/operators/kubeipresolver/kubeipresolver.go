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
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
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

// TODO: Generalize this. Will be useful for other gadgets/operators too
type k8sInventoryCache struct {
	clientset *kubernetes.Clientset

	pods atomic.Pointer[v1.PodList]
	svcs atomic.Pointer[v1.ServiceList]

	exit           chan struct{}
	ticker         *time.Ticker
	tickerDuration time.Duration

	useCount      int
	useCountMutex sync.Mutex
}

func newCache(tickerDuration time.Duration) (*k8sInventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}

	return &k8sInventoryCache{
		clientset:      clientset,
		tickerDuration: tickerDuration,
	}, nil
}

func (cache *k8sInventoryCache) loop() {
	for {
		select {
		case <-cache.exit:
			return
		case <-cache.ticker.C:
			cache.update()
		}
	}
}

func (cache *k8sInventoryCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
	}
	if cache.ticker != nil {
		cache.ticker.Stop()
	}
}

func (cache *k8sInventoryCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.update()
		cache.exit = make(chan struct{})
		cache.ticker = time.NewTicker(cache.tickerDuration)
		go cache.loop()
	}
	cache.useCount++
}

func (cache *k8sInventoryCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *k8sInventoryCache) update() {
	pods, err := cache.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing pods: %v", err)
		return
	}
	cache.pods.Store(pods)

	svcs, err := cache.clientset.CoreV1().Services("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Errorf("listing services: %s", err)
		return
	}
	cache.svcs.Store(svcs)
}

func (cache *k8sInventoryCache) GetPods() *v1.PodList {
	return cache.pods.Load()
}

func (cache *k8sInventoryCache) GetSvcs() *v1.ServiceList {
	return cache.svcs.Load()
}

type KubeIPResolver struct {
	k8sInventory *k8sInventoryCache
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
	k8sInventory, err := newCache(1 * time.Second)
	if err != nil {
		return fmt.Errorf("creating new k8sInventoryCache: %w", err)
	}
	k.k8sInventory = k8sInventory
	return nil
}

func (k *KubeIPResolver) Close() error {
	k.k8sInventory.Close()
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
	m.manager.k8sInventory.Start()
	return nil
}

func (m *KubeIPResolverInstance) PostGadgetRun() error {
	m.manager.k8sInventory.Stop()
	return nil
}

func (m *KubeIPResolverInstance) enrich(ev any) {
	additionalInfo, _ := ev.(KubeNetworkInformation)
	containerInfo, _ := ev.(operators.ContainerInfoGetters)

	additionalInfo.SetRemoteKind(types.RemoteKindOther)

	pods := m.manager.k8sInventory.GetPods()
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

	svcs := m.manager.k8sInventory.GetSvcs()

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
