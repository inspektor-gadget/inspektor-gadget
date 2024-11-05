// Copyright 2024 The Inspektor Gadget authors
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

package k8sconfigmapstore

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

const (
	GadgetInstance = "gadget-instance"

	gadgetNamespace = "gadget"

	gadgetImage    = "gadgetImage"
	gadgetLogLevel = "gadgetLogLevel"
	gadgetNodes    = "gadgetNodes"
	gadgetTags     = "gadgetTags"
	gadgetTimeout  = "gadgetTimeout"
)

type Store struct {
	api.UnimplementedGadgetInstanceManagerServer
	nodeName    string
	store       cache.Store
	queue       workqueue.TypedRateLimitingInterface[string]
	informer    cache.Controller
	clientset   *kubernetes.Clientset
	instanceMgr *instancemanager.Manager
}

func New(mgr *instancemanager.Manager) (*Store, error) {
	s := &Store{
		instanceMgr: mgr,
		nodeName:    os.Getenv("NODE_NAME"),
	}
	err := s.init()
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) init() error {
	log.Infof("initializing ConfigMap store for node %q", s.nodeName)
	config, err := rest.InClusterConfig()
	if err != nil {
		return err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	s.clientset = clientset

	selector := labels.SelectorFromSet(map[string]string{"type": GadgetInstance}).String()

	configMapListWatcher := cache.NewFilteredListWatchFromClient(clientset.CoreV1().RESTClient(), "configmaps", gadgetNamespace, func(options *v1.ListOptions) {
		options.LabelSelector = selector
	})

	// create the workqueue
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	// Bind the workqueue to a cache with the help of an informer. This way we make sure that
	// whenever the cache is updated, the ConfigMap key is added to the workqueue.
	// Note that when we finally process the item from the workqueue, we might see a newer version
	// of the ConfigMap than the version which was responsible for triggering the update.
	store, controller := cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: configMapListWatcher,
		ObjectType:    &corev1.ConfigMap{},
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
	})

	s.queue = queue
	s.store = store
	s.informer = controller
	return nil
}

func (s *Store) runController() {
	stopChan := make(chan struct{})

	defer s.queue.ShutDown()
	go s.informer.Run(stopChan)

	if !cache.WaitForCacheSync(stopChan, s.informer.HasSynced) {
		runtime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}

	wait.Until(s.runWorker, time.Second, stopChan)
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

	// Invoke the method containing the business logic
	err := s.reconcile(key)

	// Handle the error if something went wrong during the execution of the business logic
	s.handleErr(err, key)
	return true
}

func (s *Store) reconcile(key string) error {
	log.Infof("reconciling %s", key)
	obj, exists, err := s.store.GetByKey(key)
	if err != nil {
		log.Errorf("fetching object with key %s from store failed with %v", key, err)
		return err
	}

	namespacedName := strings.SplitN(key, "/", 2)
	if len(namespacedName) != 2 {
		return fmt.Errorf("invalid key; expected %q, got %q", "namespace/name", key)
	}

	err = s.instanceMgr.RemoveGadget(namespacedName[1])
	if !exists {
		// instance was deleted, so return the result of the deletion
		return err
	}

	configMap, ok := obj.(*corev1.ConfigMap)
	if !ok {
		return fmt.Errorf("unexpected type: expected *corev1.ConfigMap, got %T", obj)
	}
	instance, err := configMapToGadgetInstance(configMap)
	if err != nil {
		return fmt.Errorf("converting configMap to gadgetInstance: %w", err)
	}
	if len(instance.Nodes) > 0 && !slices.Contains(instance.Nodes, s.nodeName) {
		return nil
	}

	log.Infof("starting gadget %q", configMap.Name)
	s.instanceMgr.RunGadget(instance)
	return nil
}

// handleErr checks if an error happened and makes sure we will retry later.
func (s *Store) handleErr(err error, key string) {
	if err == nil {
		// Forget about the #AddRateLimited history of the key on every successful synchronization.
		// This ensures that future processing of updates for this key is not delayed because of
		// an outdated error history.
		s.queue.Forget(key)
		return
	}

	// This controller retries 5 times if something goes wrong. After that, it stops trying.
	if s.queue.NumRequeues(key) < 5 {
		log.Infof("Error syncing ConfigMap %v: %v", key, err)

		// Re-enqueue the key rate limited. Based on the rate limiter on the
		// queue and the re-enqueue history, the key will be processed later again.
		s.queue.AddRateLimited(key)
		return
	}

	s.queue.Forget(key)
	// Report to an external entity that, even after several retries, we could not successfully process this key
	runtime.HandleError(err)
}

// CreateGadgetInstance installs the gadget as a new config map to the cluster
func (s *Store) CreateGadgetInstance(ctx context.Context, req *api.CreateGadgetInstanceRequest) (*api.CreateGadgetInstanceResponse, error) {
	log.Debugf("create gadget instance: %+v", req.GadgetInstance.GadgetConfig)

	tmpTrue := true
	cmap := &corev1.ConfigMap{
		TypeMeta: v1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      req.GadgetInstance.Id,
			Namespace: gadgetNamespace,
			Labels: map[string]string{
				"type": GadgetInstance,
				"name": req.GadgetInstance.Name,
			},
			Annotations: map[string]string{
				gadgetImage:    req.GadgetInstance.GadgetConfig.ImageName,
				gadgetTags:     strings.Join(req.GadgetInstance.Tags, ","),
				gadgetTimeout:  fmt.Sprintf("%d", req.GadgetInstance.GadgetConfig.Timeout),
				gadgetLogLevel: fmt.Sprintf("%d", req.GadgetInstance.GadgetConfig.LogLevel),
				gadgetNodes:    strings.Join(req.GadgetInstance.Nodes, ","),
			},
		},
		Immutable:  &tmpTrue,
		Data:       req.GadgetInstance.GadgetConfig.ParamValues,
		BinaryData: nil,
	}

	_, err := s.clientset.CoreV1().ConfigMaps(gadgetNamespace).Create(ctx, cmap, v1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	return &api.CreateGadgetInstanceResponse{
		Result:         0,
		GadgetInstance: req.GadgetInstance,
	}, nil
}

// ListGadgetInstances lists all installed gadget instances stored as config maps in the cluster
func (s *Store) ListGadgetInstances(ctx context.Context, request *api.ListGadgetInstancesRequest) (*api.ListGadgetInstanceResponse, error) {
	configMaps := s.store.List()
	gadgets := make([]*api.GadgetInstance, 0, len(configMaps))
	for _, configMap := range configMaps {
		instance, err := configMapToGadgetInstance(configMap.(*corev1.ConfigMap))
		if err != nil {
			return nil, fmt.Errorf("converting configMap to gadgetInstance: %w", err)
		}
		gadgets = append(gadgets, instance)
	}
	return &api.ListGadgetInstanceResponse{GadgetInstances: gadgets}, nil
}

// RemoveGadgetInstance removes the corresponding config map of the given gadget instance from the cluster
func (s *Store) RemoveGadgetInstance(ctx context.Context, id *api.GadgetInstanceId) (*api.StatusResponse, error) {
	err := s.clientset.CoreV1().ConfigMaps(gadgetNamespace).Delete(ctx, id.Id, v1.DeleteOptions{})
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

// GetGadgetInstance returns the configuration of the given gadget instance
func (s *Store) GetGadgetInstance(ctx context.Context, req *api.GadgetInstanceId) (*api.GadgetInstance, error) {
	configMap, ok, err := s.store.GetByKey(gadgetNamespace + "/" + req.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return configMapToGadgetInstance(configMap.(*corev1.ConfigMap))
}

func (s *Store) ResumeStoredGadgets() error {
	go s.runController()
	return nil
}

func configMapToGadgetInstance(cm *corev1.ConfigMap) (*api.GadgetInstance, error) {
	timeout, err := strconv.ParseInt(cm.Annotations[gadgetTimeout], 10, 64)
	if err != nil && cm.Annotations[gadgetTimeout] != "" {
		return nil, fmt.Errorf("parsing %s annotation for %q: %w", gadgetTimeout, cm.Name, err)
	}
	logLevel, err := strconv.ParseUint(cm.Annotations[gadgetLogLevel], 10, 32)
	if err != nil && cm.Annotations[gadgetLogLevel] != "" {
		return nil, fmt.Errorf("parsing %s annotation for %q: %w", gadgetLogLevel, cm.Name, err)
	}
	nodes := strings.Split(cm.Annotations["gadgetNodes"], ",")
	if len(nodes) == 1 && nodes[0] == "" {
		// no nodes given, make sure the array is empty
		nodes = []string{}
	}
	return &api.GadgetInstance{
		Id: cm.Name,
		GadgetConfig: &api.GadgetRunRequest{
			ImageName:   cm.Annotations[gadgetImage],
			ParamValues: cm.Data,
			LogLevel:    uint32(logLevel),
			Timeout:     timeout,
			Version:     api.VersionGadgetRunProtocol,
		},
		Nodes:       nodes,
		Name:        cm.Labels["name"],
		Tags:        strings.Split(cm.Annotations[gadgetTags], ","),
		TimeCreated: cm.CreationTimestamp.Unix(),
	}, nil
}
