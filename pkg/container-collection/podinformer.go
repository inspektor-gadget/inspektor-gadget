// Copyright 2017 The Kubernetes Authors.
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

/* Code based on the official client-go example:
 * https://github.com/kubernetes/client-go/blob/master/examples/workqueue/main.go
 */

package containercollection

import (
	"context"
	"errors"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	kubeletpodsv1alpha1 "k8s.io/kubelet/pkg/apis/pods/v1alpha1"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

type PodInformer struct {
	store    cache.Store
	queue    workqueue.TypedRateLimitingInterface[string]
	informer cache.Controller

	// cancel is set for the gRPC path; nil for the REST path.
	cancel context.CancelFunc

	stop           chan struct{}
	updatedPodChan chan *v1.Pod
	deletedPodChan chan string
	wg             sync.WaitGroup

	emptyContainerIDOnce sync.Once
}

func NewPodInformer(node string) (*PodInformer, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	config.UserAgent = version.UserAgent() + " (container-collection/NewPodInformer)"
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	podListWatcher := cache.NewListWatchFromClient(clientset.CoreV1().RESTClient(), "pods", "", fields.OneTermEqualSelector("spec.nodeName", node))

	// creates the queue
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	store, informer := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: podListWatcher,
		ObjectType:    &v1.Pod{},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					queue.Add(key)
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					queue.Add(key)
				}
			},
			DeleteFunc: func(obj interface{}) {
				// IndexerInformer uses a delta queue, therefore for deletes we have to use this
				// key function.
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					queue.Add(key)
				}
			},
		},
		ResyncPeriod: 0,
	})

	p := &PodInformer{
		store:          store,
		queue:          queue,
		informer:       informer,
		stop:           make(chan struct{}),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
	}

	// Now let's start the controller
	go p.Run(1, p.stop)

	return p, nil
}

func (p *PodInformer) Stop() {
	// For the gRPC path, cancel the context; for REST, close the stop channel.
	if p.cancel != nil {
		p.cancel()
	} else {
		close(p.stop)
	}

	// wait for workers to end before closing channels to avoid
	// writing to closed channels
	p.wg.Wait()

	close(p.updatedPodChan)
	close(p.deletedPodChan)
}

func (p *PodInformer) UpdatedChan() <-chan *v1.Pod {
	return p.updatedPodChan
}

func (p *PodInformer) DeletedChan() <-chan string {
	return p.deletedPodChan
}

func (p *PodInformer) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := p.queue.Get()
	if quit {
		return false
	}

	defer p.queue.Done(key)

	p.notifyChans(key)
	return true
}

// notifyChans passes the event to the channels configured by the user
func (p *PodInformer) notifyChans(key string) error {
	obj, exists, err := p.store.GetByKey(key)
	if err != nil {
		log.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}
	defer p.queue.Forget(key)

	if !exists {
		p.deletedPodChan <- key
		return nil
	}

	p.updatedPodChan <- obj.(*v1.Pod)
	return nil
}

func (p *PodInformer) Run(threadiness int, stopCh chan struct{}) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer p.queue.ShutDown()
	log.Info("Starting Pod controller")

	go p.informer.Run(stopCh)

	// Wait for all involved caches to be synced, before processing items from the queue is started
	if !cache.WaitForCacheSync(stopCh, p.informer.HasSynced) {
		runtime.HandleError(errors.New("timed out waiting for caches to sync"))
		return
	}

	for i := 0; i < threadiness; i++ {
		p.wg.Add(1)
		go wait.Until(p.runWorker, time.Second, stopCh)
	}

	<-stopCh
	log.Info("Stopping Pod controller")
}

// newKubeletGRPCPodInformer creates a PodInformer backed by the Kubelet gRPC
// pods API (KEP-4188, PodsAPI feature gate, Kubernetes 1.36+ alpha). It
// replaces the kube-apiserver REST watch with a node-local WatchPods stream
// over the Unix socket.
func newKubeletGRPCPodInformer(parent context.Context, client kubeletpodsv1alpha1.PodsClient, node string) (*PodInformer, error) {
	ctx, cancel := context.WithCancel(parent)
	p := &PodInformer{
		cancel:         cancel,
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		wait.JitterUntilWithContext(ctx, func(ctx context.Context) {
			p.watchStream(ctx, client, node)
		}, 1*time.Second, 0.5, true)
	}()
	return p, nil
}

func (p *PodInformer) watchStream(ctx context.Context, client kubeletpodsv1alpha1.PodsClient, node string) {
	stream, err := client.WatchPods(ctx, &kubeletpodsv1alpha1.WatchPodsRequest{})
	if err != nil {
		if ctx.Err() == nil {
			log.Debugf("Kubelet pods API WatchPods: %v", err)
		}
		return
	}
	for {
		ev, err := stream.Recv()
		if err != nil {
			if ctx.Err() == nil {
				log.Debugf("Kubelet pods API stream error: %v", err)
			}
			return
		}
		p.handleWatchEvent(ctx, ev, node)
	}
}

func (p *PodInformer) handleWatchEvent(ctx context.Context, ev *kubeletpodsv1alpha1.WatchPodsEvent, node string) {
	switch ev.GetType() {
	case kubeletpodsv1alpha1.EventType_ADDED, kubeletpodsv1alpha1.EventType_MODIFIED:
		var pod v1.Pod
		if err := pod.Unmarshal(ev.GetPod()); err != nil {
			log.Warnf("Kubelet pods API: cannot unmarshal pod: %v", err)
			return
		}
		if pod.Spec.NodeName != "" && pod.Spec.NodeName != node {
			return
		}
		allStatuses := append(pod.Status.ContainerStatuses, pod.Status.InitContainerStatuses...)
		if len(allStatuses) > 0 {
			allEmpty := true
			for _, cs := range allStatuses {
				if cs.ContainerID != "" {
					allEmpty = false
					break
				}
			}
			if allEmpty {
				p.emptyContainerIDOnce.Do(func() {
					log.Warnf("Kubelet pods API: pod %s/%s has no container IDs yet; CRI may not have assigned them", pod.Namespace, pod.Name)
				})
			}
		}
		select {
		case <-ctx.Done():
			return
		case p.updatedPodChan <- &pod:
		}
	case kubeletpodsv1alpha1.EventType_DELETED:
		var pod v1.Pod
		if err := pod.Unmarshal(ev.GetPod()); err != nil {
			log.Warnf("Kubelet pods API: cannot unmarshal pod: %v", err)
			return
		}
		key := pod.Namespace + "/" + pod.Name
		select {
		case <-ctx.Done():
			return
		case p.deletedPodChan <- key:
		}
	case kubeletpodsv1alpha1.EventType_INITIAL_SYNC_COMPLETE, kubeletpodsv1alpha1.EventType_UNSPECIFIED:
		// no-op: sync marker, nothing to propagate
	}
}

func (p *PodInformer) runWorker() {
	defer p.wg.Done()

	for p.processNextItem() {
	}
}
