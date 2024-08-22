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

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type PodInformer struct {
	store    cache.Store
	queue    workqueue.TypedRateLimitingInterface[string]
	informer cache.Controller

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

func (p *PodInformer) runWorker() {
	defer p.wg.Done()

	for p.processNextItem() {
	}
}
