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
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type podEvent struct {
	pod     *v1.Pod
	deleted bool
}

type podInformerHandler struct {
	queue workqueue.TypedRateLimitingInterface[podEvent]
}

func (p *podInformerHandler) OnAdd(obj any, _ bool) {
	switch o := obj.(type) {
	case *v1.Pod:
		p.queue.Add(podEvent{
			pod:     o,
			deleted: false,
		})
	}
}

func (p *podInformerHandler) OnUpdate(_, newObj any) {
	switch o := newObj.(type) {
	case *v1.Pod:
		p.queue.Add(podEvent{
			pod:     o,
			deleted: false,
		})
	}
}

func (p *podInformerHandler) OnDelete(obj any) {
	switch o := obj.(type) {
	case *v1.Pod:
		p.queue.Add(podEvent{
			pod:     o,
			deleted: true,
		})
	}
}

type PodInformer struct {
	factory  informers.SharedInformerFactory
	informer podInformerHandler

	stop           chan struct{}
	updatedPodChan chan *v1.Pod
	deletedPodChan chan string
	wg             sync.WaitGroup
}

func NewPodInformer(node string) (*PodInformer, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	p := &PodInformer{
		informer: podInformerHandler{
			queue: workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[podEvent]()),
		},
		stop:           make(chan struct{}),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
	}

	modifyListOptions := func(options *metaV1.ListOptions) {
		options.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", node).String()
	}
	p.factory = informers.NewSharedInformerFactoryWithOptions(clientset, 0, informers.WithTweakListOptions(modifyListOptions))
	p.factory.Core().V1().Pods().Informer().AddEventHandler(&p.informer)

	// Now let's start the controller
	go p.Run(1, p.stop)

	return p, nil
}

func (p *PodInformer) Stop() {
	// tell all workers to end
	close(p.stop)

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
	e, quit := p.informer.queue.Get()
	if quit {
		return false
	}

	defer p.informer.queue.Done(e)

	p.notifyChans(e)
	return true
}

// notifyChans passes the event to the channels configured by the user
func (p *PodInformer) notifyChans(e podEvent) error {
	defer p.informer.queue.Forget(e)

	if e.deleted {
		// IndexerInformer uses a delta queue, therefore for deletes we have to use this
		// key function.
		key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(e.pod)
		if err == nil {
			p.deletedPodChan <- key
		}
		return nil
	}

	p.updatedPodChan <- e.pod
	return nil
}

func (p *PodInformer) Run(threadiness int, stopCh chan struct{}) {
	defer runtime.HandleCrash()

	// Let the workers stop when we are done
	defer p.informer.queue.ShutDown()
	log.Info("Starting Pod controller")

	p.factory.Start(stopCh)
	p.factory.WaitForCacheSync(stopCh)

	for i := 0; i < threadiness; i++ {
		p.wg.Add(1)
		go wait.Until(p.runWorker, time.Second, stopCh)
	}

	<-stopCh
	log.Info("Stopping Pod controller")
}

func (p *PodInformer) runWorker() {
	defer p.wg.Done()

	for p.processNextItem() {
	}
}
