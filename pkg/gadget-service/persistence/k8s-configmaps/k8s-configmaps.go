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

package k8sconfigmaps

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/pkg/namesgenerator"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence"
)

const (
	GadgetConfig = "gadget-config"
)

type Store struct {
	indexer        cache.Indexer
	queue          workqueue.RateLimitingInterface
	informer       cache.Controller
	clientset      *kubernetes.Clientset
	persistenceMgr *persistence.Manager
}

func NewStore(mgr *persistence.Manager) (*Store, error) {
	log.SetLevel(log.DebugLevel)
	s := &Store{
		persistenceMgr: mgr,
	}
	err := s.init()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	s.clientset = clientset

	selector := labels.SelectorFromSet(labels.Set(map[string]string{"type": GadgetConfig})).String()

	configMapListWatcher := cache.NewFilteredListWatchFromClient(clientset.CoreV1().RESTClient(), "configmaps", "gadget", func(options *v1.ListOptions) {
		options.LabelSelector = selector
	})

	// create the workqueue
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	// Bind the workqueue to a cache with the help of an informer. This way we make sure that
	// whenever the cache is updated, the ConfigMap key is added to the workqueue.
	// Note that when we finally process the item from the workqueue, we might see a newer version
	// of the ConfigMap than the version which was responsible for triggering the update.
	indexer, informer := cache.NewIndexerInformer(configMapListWatcher, &corev1.ConfigMap{}, 0, cache.ResourceEventHandlerFuncs{
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
	}, cache.Indexers{})

	s.queue = queue
	s.indexer = indexer
	s.informer = informer

	go s.runController()
	return nil
}

func (s *Store) runController() {
	stopChan := make(chan struct{})

	defer runtime.HandleCrash()

	defer s.queue.ShutDown()
	go s.informer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, s.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	go wait.Until(s.runWorker, time.Second, stopChan)

	<-stopChan
}

func (s *Store) runWorker() {
	for s.processNextItem() {
	}
}

func (s *Store) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := s.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because two ConfigMaps with the same key are never processed in
	// parallel.
	defer s.queue.Done(key)

	// // Invoke the method containing the business logic
	err := s.reconcile(key.(string))
	//
	// // Handle the error if something went wrong during the execution of the business logic
	s.handleErr(err, key)
	return true
}

func (s *Store) reconcile(key string) error {
	log.Printf("reconciling %s", key)
	obj, exists, err := s.indexer.GetByKey(key)
	if err != nil {
		klog.Errorf("Fetching object with key %s from store failed with %v", key, err)
		return err
	}

	if !exists {
		fmt.Printf("ConfigMap %s does not exist anymore\n", key)
		namespacedName := strings.SplitN(key, "/", 2)
		if len(namespacedName) != 2 {
			return fmt.Errorf("invalid key %q", key)
		}
		s.persistenceMgr.RemoveGadget(namespacedName[1])
		return nil
	}

	// Note that you also have to check the uid if you have a local controlled resource, which
	// is dependent on the actual instance, to detect that a ConfigMap was recreated with the same name
	log.Debugf("adding new gadget %q", obj.(*corev1.ConfigMap).GetName())

	configMap := obj.(*corev1.ConfigMap)

	if configMap.Annotations["gadgetStatus"] == "stopped" {
		log.Printf("stopping gadget %q", configMap.Name)
		s.persistenceMgr.StopGadget(configMap.Name)
		return nil
	}

	log.Printf("starting gadget %q", configMap.Name)
	gadget := &api.GadgetRunRequest{
		GadgetName:     configMap.Annotations["gadgetName"],
		GadgetCategory: configMap.Annotations["gadgetCategory"],
		Params:         configMap.Data,
		Nodes:          nil,
		FanOut:         false,
		LogLevel:       0,
		Timeout:        0,
	}

	s.persistenceMgr.RunGadget(configMap.Name, gadget)
	return nil
}

// handleErr checks if an error happened and makes sure we will retry later.
func (s *Store) handleErr(err error, key interface{}) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		s.queue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if s.queue.NumRequeues(key) < 5 {
		klog.Infof("Error syncing ConfigMap %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		s.queue.AddRateLimited(key)
		return
	}

	s.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	runtime.HandleError(err)
}

// InstallPersistentGadget should install the gadget as a new config map to the cluster
func (s *Store) InstallPersistentGadget(ctx context.Context, req *api.InstallPersistentGadgetRequest) (*api.InstallPersistentGadgetResponse, error) {
	log.Debugf("install persistent gadget: %+v", req.PersistentGadget.GadgetInfo)

	idBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, idBytes)
	if err != nil {
		return nil, fmt.Errorf("could not build gadget id")
	}
	id := hex.EncodeToString(idBytes)
	req.PersistentGadget.Id = id

	if req.PersistentGadget.Name == "" {
		// We need to use dashes instead of underlines for k8s
		req.PersistentGadget.Name = strings.Replace(namesgenerator.GetRandomName(0), "_", "-", -1)
	}

	tmpTrue := true
	cmap := &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      id,
			Namespace: "gadget",
			Labels: map[string]string{
				"type": GadgetConfig,
				"name": req.PersistentGadget.Name,
			},
			Annotations: map[string]string{
				"gadgetName":     req.PersistentGadget.GadgetInfo.GadgetName,
				"gadgetCategory": req.PersistentGadget.GadgetInfo.GadgetCategory,
				"gadgetTags":     strings.Join(req.PersistentGadget.Tags, ","),
				"gadgetTimeout":  fmt.Sprintf("%d", req.PersistentGadget.GadgetInfo.Timeout),
				"gadgetLogLevel": fmt.Sprintf("%d", req.PersistentGadget.GadgetInfo.LogLevel),
			},
		},
		Immutable:  &tmpTrue,
		Data:       req.PersistentGadget.GadgetInfo.Params,
		BinaryData: nil,
	}

	_, err = s.clientset.CoreV1().ConfigMaps("gadget").Create(ctx, cmap, v1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return &api.InstallPersistentGadgetResponse{
		Result:           0,
		PersistentGadget: req.PersistentGadget,
	}, nil
}

// ListPersistentGadgets should list all installed gadget instances stored as config maps in the cluster
func (s *Store) ListPersistentGadgets(ctx context.Context, request *api.ListPersistentGadgetRequest) (*api.ListPersistentGadgetResponse, error) {
	gadgets := make([]*api.PersistentGadget, 0)
	configMaps := s.indexer.List()
	for _, configMap := range configMaps {
		gadgets = append(gadgets, configMapToPersistentGadget(configMap.(*corev1.ConfigMap)))
	}
	return &api.ListPersistentGadgetResponse{PersistentGadgets: gadgets}, nil
}

// RemovePersistentGadget should remove the corresponding config map of the given gadget instance from the cluster
func (s *Store) RemovePersistentGadget(ctx context.Context, id *api.PersistentGadgetId) (*api.StatusResponse, error) {
	err := s.clientset.CoreV1().ConfigMaps("gadget").Delete(ctx, id.Id, v1.DeleteOptions{})
	if err != nil {
		return &api.StatusResponse{
			Result:  1,
			Message: err.Error(),
		}, nil
	}
	return &api.StatusResponse{
		Result:  0,
		Message: "",
	}, nil
}

func (s *Store) StopPersistentGadget(ctx context.Context, id *api.PersistentGadgetId) (*api.StatusResponse, error) {
	configMap, err := s.clientset.CoreV1().ConfigMaps("gadget").Get(ctx, id.Id, v1.GetOptions{})
	if err != nil {
		return nil, err
	}

	configMap.Annotations["gadgetStatus"] = "stopped"
	_, err = s.clientset.CoreV1().ConfigMaps("gadget").Update(ctx, configMap, v1.UpdateOptions{})

	if err != nil {
		return nil, err
	}
	return &api.StatusResponse{
		Result: 0,
	}, nil
}

// GetPersistentGadget should return the configuration of the given gadget instance
func (s *Store) GetPersistentGadget(ctx context.Context, req *api.PersistentGadgetId) (*api.PersistentGadget, error) {
	configMap, ok, err := s.indexer.GetByKey("gadget/" + req.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return configMapToPersistentGadget(configMap.(*corev1.ConfigMap)), nil
}

func configMapToPersistentGadget(cm *corev1.ConfigMap) *api.PersistentGadget {
	timeout, _ := strconv.ParseInt(cm.Annotations["gadgetTimeout"], 10, 64)
	logLevel, _ := strconv.ParseUint(cm.Annotations["gadgetLogLevel"], 10, 64)
	return &api.PersistentGadget{
		Id: cm.Name,
		GadgetInfo: &api.GadgetRunRequest{
			GadgetName:     cm.Annotations["gadgetName"],
			GadgetCategory: cm.Annotations["gadgetCategory"],
			Params:         cm.Data,
			Nodes:          strings.Split(cm.Annotations["nodes"], ","),
			FanOut:         false,
			LogLevel:       uint32(logLevel),
			Timeout:        timeout,
		},
		Name:        cm.Labels["name"],
		Tags:        strings.Split(cm.Annotations["gadgetTags"], ","),
		TimeCreated: cm.CreationTimestamp.Unix(),
		Paused:      false,
	}
}
