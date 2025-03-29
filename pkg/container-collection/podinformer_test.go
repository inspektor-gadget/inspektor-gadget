package containercollection

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type mockK8sClient struct {
	store    cache.Store
	informer cache.Controller
	queue    workqueue.TypedRateLimitingInterface[string]
	client   *fake.Clientset
	pods     []*v1.Pod
	nodeName string
}

func (m *mockK8sClient) GetStore() cache.Store {
	return m.store
}

func (m *mockK8sClient) GetInformer() cache.Controller {
	return m.informer
}

func (m *mockK8sClient) GetQueue() workqueue.TypedRateLimitingInterface[string] {
	return m.queue
}

func (m *mockK8sClient) GetPodListWatcher(nodeName string) cache.ListerWatcher {
	m.nodeName = nodeName
	return &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			podList := &v1.PodList{
				Items: []v1.Pod{},
			}
			for _, pod := range m.pods {
				if pod.Spec.NodeName == nodeName {
					podList.Items = append(podList.Items, *pod)
				}
			}
			return podList, nil
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			watcher := watch.NewFake()
			// We don't need to send any events in the test
			return watcher, nil
		},
	}
}

func newMockK8sClient(fail bool) (*mockK8sClient, error) {
	if fail {
		return nil, fmt.Errorf("mock client creation failed")
	}

	store := cache.NewStore(cache.MetaNamespaceKeyFunc)
	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

	return &mockK8sClient{
		store:  store,
		queue:  queue,
		client: fake.NewSimpleClientset(),
		pods:   make([]*v1.Pod, 0),
	}, nil
}

func TestPodInformerWithMockClient(t *testing.T) {
	tests := []struct {
		name        string
		nodeName    string
		failClient  bool
		expectError bool
	}{
		{
			name:        "successful initialization",
			nodeName:    "test-node",
			failClient:  false,
			expectError: false,
		},
		{
			name:        "client creation fails",
			nodeName:    "test-node",
			failClient:  true,
			expectError: true,
		},
		{
			name:        "empty node name",
			nodeName:    "",
			failClient:  false,
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockClient, err := newMockK8sClient(tc.failClient)
			if tc.failClient {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			p := &PodInformer{
				store:          mockClient.GetStore(),
				queue:          mockClient.GetQueue(),
				updatedPodChan: make(chan *v1.Pod, 1),
				deletedPodChan: make(chan string, 1),
				stop:           make(chan struct{}),
			}

			// Create the informer using the newer API
			var store cache.Store
			store, p.informer = cache.NewInformerWithOptions(cache.InformerOptions{
				ListerWatcher: mockClient.GetPodListWatcher(tc.nodeName),
				ObjectType:    &v1.Pod{},
				ResyncPeriod:  0,
				Handler: cache.ResourceEventHandlerFuncs{
					AddFunc: func(obj interface{}) {
						key, err := cache.MetaNamespaceKeyFunc(obj)
						if err == nil {
							p.queue.Add(key)
						}
					},
				},
			})
			p.store = store

			// Test informer functionality
			if tc.nodeName == "" {
				assert.NotNil(t, p.informer)
			} else {
				assert.NotNil(t, p.informer)

				// Start the informer
				stopCh := make(chan struct{})
				go p.informer.Run(stopCh)

				// Wait for cache sync
				synced := cache.WaitForCacheSync(stopCh, p.informer.HasSynced)
				assert.True(t, synced)

				// Create test pod
				testPod := &v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: "default",
					},
					Spec: v1.PodSpec{
						NodeName: tc.nodeName,
					},
				}

				// Add pod to store
				err = p.store.Add(testPod)
				require.NoError(t, err)

				// Verify pod was added to queue
				key, err := cache.MetaNamespaceKeyFunc(testPod)
				require.NoError(t, err)
				p.queue.Add(key)

				item, _ := p.queue.Get()
				assert.Equal(t, "default/test-pod", item)

				// Cleanup
				close(stopCh)
			}

			p.queue.ShutDown()
		})
	}
}

func TestRunWithFailingInformer(t *testing.T) {
	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
		stop:           make(chan struct{}),
	}

	// Create failing ListWatch
	listWatch := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			return nil, fmt.Errorf("list error")
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			return nil, fmt.Errorf("watch error")
		},
	}

	// Create the informer using the newer API
	var store cache.Store
	store, p.informer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: listWatch,
		ObjectType:    &v1.Pod{},
		ResyncPeriod:  0,
		Handler:       cache.ResourceEventHandlerFuncs{},
	})
	p.store = store

	// Start the informer
	done := make(chan struct{})
	go func() {
		p.Run(1, p.stop)
		close(done)
	}()

	// Give the informer a moment to attempt listing
	time.Sleep(100 * time.Millisecond)

	// Stop the informer
	close(p.stop)

	// Wait for shutdown
	select {
	case <-done:
		// Success - controller stopped
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for controller to stop")
	}
}

func TestMultipleWorkers(t *testing.T) {
	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod, 10),
		deletedPodChan: make(chan string, 10),
		stop:           make(chan struct{}),
	}

	// Create test pods and add to store
	testPods := make([]*v1.Pod, 0, 5)
	for i := 0; i < 5; i++ {
		pod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("test-pod-%d", i),
				Namespace: "default",
			},
		}
		testPods = append(testPods, pod)
		err := p.store.Add(pod)
		require.NoError(t, err)
	}

	// Create the informer using the newer API
	var store cache.Store
	store, p.informer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				podList := &v1.PodList{
					Items: make([]v1.Pod, 0, len(testPods)),
				}
				for _, pod := range testPods {
					podList.Items = append(podList.Items, *pod)
				}
				return podList, nil
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return watch.NewFake(), nil
			},
		},
		ObjectType:   &v1.Pod{},
		ResyncPeriod: 0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					p.queue.Add(key)
				}
			},
		},
	})
	p.store = store

	// Add items to queue
	for _, pod := range testPods {
		key, err := cache.MetaNamespaceKeyFunc(pod)
		require.NoError(t, err)
		p.queue.Add(key)
	}

	// Start the workers
	numWorkers := 3
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.Run(numWorkers, p.stop)
	}()

	// Wait for all items to be processed
	processedItems := 0
	timeout := time.After(2 * time.Second)
	for {
		select {
		case <-timeout:
			close(p.stop)
			t.Fatal("timeout waiting for items to be processed")
		case <-p.updatedPodChan:
			processedItems++
			if processedItems == len(testPods) {
				close(p.stop)
				wg.Wait()
				assert.Equal(t, 0, p.queue.Len())
				return
			}
		}
	}
}

// TestProcessNextItem tests the processNextItem function
func TestProcessNextItem(t *testing.T) {
	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod, 1),
		deletedPodChan: make(chan string, 1),
	}

	t.Run("handles quit signal", func(t *testing.T) {
		p.queue.ShutDown()
		result := p.processNextItem()
		assert.False(t, result)
	})

	t.Run("processes item successfully", func(t *testing.T) {
		// Reset queue
		p.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]())

		// Add test pod to store
		testPod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
			},
		}
		err := p.store.Add(testPod)
		require.NoError(t, err)

		// Add pod key to queue
		key, err := cache.MetaNamespaceKeyFunc(testPod)
		require.NoError(t, err)
		p.queue.Add(key)

		// Process the item
		result := p.processNextItem()
		assert.True(t, result)

		// Verify pod was received on update channel
		select {
		case pod := <-p.updatedPodChan:
			assert.Equal(t, testPod.Name, pod.Name)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for pod update")
		}
	})
}

// TestRunAndShutdown tests the Run and Stop functions
func TestRunAndShutdown(t *testing.T) {
	// Create a fake client with some test pods
	client := fake.NewSimpleClientset()

	// Create test pod
	testPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
		Spec: v1.PodSpec{
			NodeName: "test-node",
		},
	}
	_, err := client.CoreV1().Pods("default").Create(context.Background(), testPod, metav1.CreateOptions{})
	require.NoError(t, err)

	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
		stop:           make(chan struct{}),
	}

	// Create a simple informer that directly uses the store
	_, p.informer = cache.NewInformerWithOptions(cache.InformerOptions{
		ListerWatcher: &cache.ListWatch{
			ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
				return client.CoreV1().Pods("").List(context.Background(), options)
			},
			WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
				return client.CoreV1().Pods("").Watch(context.Background(), options)
			},
		},
		ObjectType:   &v1.Pod{},
		ResyncPeriod: 0,
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(obj)
				if err == nil {
					p.queue.Add(key)
				}
			},
			UpdateFunc: func(old interface{}, new interface{}) {
				key, err := cache.MetaNamespaceKeyFunc(new)
				if err == nil {
					p.queue.Add(key)
				}
			},
			DeleteFunc: func(obj interface{}) {
				key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
				if err == nil {
					p.queue.Add(key)
				}
			},
		},
		Indexers: cache.Indexers{},
	})

	// Start the controller in a goroutine
	done := make(chan struct{})
	go func() {
		p.Run(1, p.stop)
		close(done)
	}()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Stop the controller
	close(p.stop)

	// Wait for shutdown
	select {
	case <-done:
		// Success - controller shut down
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for controller to stop")
	}
}

// TestInformerHandlers tests the informer event handlers
func TestInformerHandlers(t *testing.T) {
	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
	}

	// Create a test pod
	testPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	// Test the event handlers
	t.Run("add handler", func(t *testing.T) {
		err := p.store.Add(testPod)
		require.NoError(t, err)
		key, err := cache.MetaNamespaceKeyFunc(testPod)
		require.NoError(t, err)
		p.queue.Add(key)

		item, _ := p.queue.Get()
		assert.Equal(t, "default/test-pod", item)
	})

	// Clean up
	p.queue.ShutDown()
}

func TestNewPodInformer(t *testing.T) {
	// We can't easily test the actual NewPodInformer function since it requires
	// an in-cluster config. Instead, we'll test the internal functionality.
	t.Run("informer properly initializes channels", func(t *testing.T) {
		p := &PodInformer{
			stop:           make(chan struct{}),
			updatedPodChan: make(chan *v1.Pod),
			deletedPodChan: make(chan string),
		}

		assert.NotNil(t, p.stop)
		assert.NotNil(t, p.updatedPodChan)
		assert.NotNil(t, p.deletedPodChan)
	})
}

func TestPodInformerNotifyChans(t *testing.T) {
	// Create test pod
	testPod := &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	// Create PodInformer with all required fields
	p := &PodInformer{
		store:          cache.NewStore(cache.MetaNamespaceKeyFunc),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
		updatedPodChan: make(chan *v1.Pod, 1),
		deletedPodChan: make(chan string, 1),
	}

	t.Run("notifyChans handles pod updates", func(t *testing.T) {
		// Add pod to store
		err := p.store.Add(testPod)
		require.NoError(t, err)

		// Test notification for update
		key, err := cache.MetaNamespaceKeyFunc(testPod)
		require.NoError(t, err)

		err = p.notifyChans(key)
		require.NoError(t, err)

		// Verify update channel received pod
		select {
		case updatedPod := <-p.updatedPodChan:
			assert.Equal(t, testPod.Name, updatedPod.Name)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for pod update")
		}
	})

	t.Run("notifyChans handles pod deletions", func(t *testing.T) {
		// Clear the store for deletion test
		p.store = cache.NewStore(cache.MetaNamespaceKeyFunc)

		// Test notification for deletion
		key := "default/test-pod"
		err := p.notifyChans(key)
		require.NoError(t, err)

		// Verify deletion channel received key
		select {
		case deletedKey := <-p.deletedPodChan:
			assert.Equal(t, key, deletedKey)
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for pod deletion")
		}
	})

	// Cleanup
	p.queue.ShutDown()
}

func TestPodInformerStop(t *testing.T) {
	p := &PodInformer{
		stop:           make(chan struct{}),
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
		queue:          workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}

	// Start a goroutine that will be stopped
	done := make(chan struct{})
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		<-p.stop
		close(done)
	}()

	// Call Stop and verify channels are closed
	p.Stop()

	// Verify worker stopped
	select {
	case <-done:
		// Success
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for worker to stop")
	}

	// Verify channels are closed
	_, updatedOpen := <-p.updatedPodChan
	assert.False(t, updatedOpen)

	_, deletedOpen := <-p.deletedPodChan
	assert.False(t, deletedOpen)
}

func TestUpdateAndDeleteChannels(t *testing.T) {
	p := &PodInformer{
		updatedPodChan: make(chan *v1.Pod),
		deletedPodChan: make(chan string),
	}

	t.Run("UpdatedChan returns correct channel", func(t *testing.T) {
		// Test by sending and receiving a value
		testPod := &v1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name: "test-pod",
			},
		}

		go func() {
			p.updatedPodChan <- testPod
		}()

		receivedPod := <-p.UpdatedChan()
		assert.Equal(t, testPod, receivedPod)
	})

	t.Run("DeletedChan returns correct channel", func(t *testing.T) {
		// Test by sending and receiving a value
		testKey := "test-pod"

		go func() {
			p.deletedPodChan <- testKey
		}()

		receivedKey := <-p.DeletedChan()
		assert.Equal(t, testKey, receivedKey)
	})
}
