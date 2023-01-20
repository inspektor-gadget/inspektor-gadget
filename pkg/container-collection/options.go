// Copyright 2019-2021 The Inspektor Gadget authors
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

package containercollection

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	ociannotations "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/oci-annotations"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runcfanotify"
)

var netnsHost uint64

func init() {
	var err error
	netnsHost, err = containerutils.GetNetNs(os.Getpid())
	if err != nil {
		panic(fmt.Sprintf("getting host net ns inode: %s", err))
	}
}

func enrichContainerWithContainerData(containerData *runtimeclient.ContainerData, container *Container) {
	// Runtime
	container.ID = containerData.ID
	container.Runtime = containerData.Runtime

	// Kubernetes
	container.Namespace = containerData.PodNamespace
	container.Podname = containerData.PodName
	container.PodUID = containerData.PodUID

	// Notice we are temporarily using the runtime container name as the
	// Kubernetes container name because the Container struct doesn't have that
	// field, and we don't support filtering by runtime container name yet.
	container.Name = containerData.Name
}

func containerRuntimeEnricher(
	runtimeName string,
	runtimeClient runtimeclient.ContainerRuntimeClient,
	container *Container,
) bool {
	// Is container already enriched? Notice that, at this point, the container
	// was already enriched with the PID by the hook.
	if container.IsEnriched() {
		return true
	}
	containerData, err := runtimeClient.GetContainer(container.ID)
	if err != nil {
		// Temporary dropping pause container. See issue
		// https://github.com/inspektor-gadget/inspektor-gadget/issues/1095.
		if errors.Is(err, runtimeclient.ErrPauseContainer) {
			log.Warnf("Runtime enricher (%s): failed to get container: %s",
				runtimeName, err)
			return false
		}

		// Container could be managed by another runtime, don't drop it.
		return true
	}

	enrichContainerWithContainerData(containerData, container)

	return true
}

// WithMultipleContainerRuntimesEnrichment is a wrapper for
// WithContainerRuntimeEnrichment() to allow caller to add multiple runtimes in
// one single call.
//
// ContainerCollection.Initialize(WithMultipleContainerRuntimesEnrichment([]*RuntimeConfig)...)
func WithMultipleContainerRuntimesEnrichment(runtimes []*containerutils.RuntimeConfig) ContainerCollectionOption {
	var opts []ContainerCollectionOption

	for _, r := range runtimes {
		opts = append(opts, WithContainerRuntimeEnrichment(r))
	}

	return func(cc *ContainerCollection) error {
		for _, o := range opts {
			err := o(cc)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// WithContainerRuntimeEnrichment automatically adds the container name using
// the requested container runtime.
//
// Pay attention if you want to use it with other enrichers that set the
// Kubernetes metadata as this enricher also collects such info from the
// runtime. Notice also that, if such info is missing in the runtime, it
// hardcodes the namespace to "default" and the podname equal to the container
// name because some gadgets need those two values to be set.
//
// ContainerCollection.Initialize(WithContainerRuntimeEnrichment(*RuntimeConfig))
func WithContainerRuntimeEnrichment(runtime *containerutils.RuntimeConfig) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		runtimeClient, err := containerutils.NewContainerRuntimeClient(runtime)
		if err != nil {
			log.Warnf("Runtime enricher (%s): failed to initialize container runtime",
				runtime.Name)
			return err
		}

		// Add the enricher for future containers even if enriching the current
		// containers fails. We do it because the runtime could be temporarily
		// unavailable and once it is up, we will start receiving the
		// notifications for its containers thus we will be able to enrich them.
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			return containerRuntimeEnricher(runtime.Name, runtimeClient, container)
		})

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			if err := runtimeClient.Close(); err != nil {
				log.Warnf("failed to close container runtime %s: %s", runtime.Name, err)
			}
		})

		// Enrich already running containers
		containers, err := runtimeClient.GetContainers()
		if err != nil {
			log.Warnf("Runtime enricher (%s): couldn't get current containers",
				runtime.Name)

			return nil
		}
		for _, container := range containers {
			if container.State != runtimeclient.StateRunning {
				log.Debugf("Runtime enricher(%s): Skip container %q (ID: %s): not running",
					runtime.Name, container.Name, container.ID)
				continue
			}

			containerDetails, err := runtimeClient.GetContainerDetails(container.ID)
			if err != nil {
				log.Debugf("Runtime enricher (%s): Skip container %q (ID: %s): couldn't find container: %s",
					runtime.Name, container.Name, container.ID, err)
				continue
			}

			var c Container
			c.Pid = uint32(containerDetails.Pid)
			enrichContainerWithContainerData(&containerDetails.ContainerData, &c)
			cc.initialContainers = append(cc.initialContainers, &c)
		}

		return nil
	}
}

// WithPodInformer uses a pod informer to get both initial containers and the
// stream of container events. It then uses the CRI interface to get the
// process ID.
//
// This cannot be used together with WithInitialKubernetesContainers() since
// the pod informer already gets initial containers.
func WithPodInformer(nodeName string) ContainerCollectionOption {
	return withPodInformer(nodeName, false)
}

// WithFallbackPodInformer uses a pod informer as a fallback mechanism to a main
// hook. If the podinformer detects a new container and it hasn't been added to
// the list of containers it means the main hook is not working fine. We warn
// the user about it.
func WithFallbackPodInformer(nodeName string) ContainerCollectionOption {
	return withPodInformer(nodeName, true)
}

func withPodInformer(nodeName string, fallbackMode bool) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		k8sClient, err := NewK8sClient(nodeName)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}

		podInformer, err := NewPodInformer(nodeName)
		if err != nil {
			return fmt.Errorf("failed to create pod informer: %w", err)
		}

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			k8sClient.Close()
			podInformer.Stop()
		})

		go func() {
			// containerIDsByKey keeps track of container ids for each key. This is
			// necessary because messages from deletedChan only gives the key
			// without additional context.
			//
			// key is "namespace/podname"
			// value is an set of containerId
			containerIDsByKey := make(map[string]map[string]struct{})

			for {
				select {
				case d, ok := <-podInformer.DeletedChan():
					if !ok {
						return
					}
					if containerIDs, ok := containerIDsByKey[d]; ok {
						for containerID := range containerIDs {
							cc.RemoveContainer(containerID)
						}
					}
				case c, ok := <-podInformer.CreatedChan():
					if !ok {
						return
					}
					key, _ := cache.MetaNamespaceKeyFunc(c)
					containerIDs, ok := containerIDsByKey[key]
					if !ok {
						containerIDs = make(map[string]struct{})
						containerIDsByKey[key] = containerIDs
					}

					// first: remove containers that are not running anymore
					nonrunning := k8sClient.GetNonRunningContainers(c)
					for _, id := range nonrunning {
						// container had not been added, no need to remove it
						if _, ok := containerIDs[id]; !ok {
							continue
						}

						cc.RemoveContainer(id)
					}

					// second: add containers that are in running state
					containers := k8sClient.PodToContainers(c)
					for _, container := range containers {
						// The container is already registered, there is not any chance the
						// PID will change, so ignore it.
						if _, ok := containerIDs[container.ID]; ok {
							continue
						}

						// Make a copy instead of passing the same pointer at
						// each iteration of the loop
						newContainer := Container{}
						newContainer = container
						if fallbackMode {
							if cc.GetContainer(container.ID) != nil {
								continue // container is already there. All good!
							}
							log.Warnf("container %s/%s/%s wasn't detected by the main hook! The fallback pod informer will add it.",
								container.Namespace, container.Podname, container.Name)
						}
						cc.AddContainer(&newContainer)

						containerIDs[container.ID] = struct{}{}
					}
				}
			}
		}()

		return nil
	}
}

// WithInitialKubernetesContainers gets initial containers from the Kubernetes
// API with the process ID from CRI.
//
// This cannot be used together with WithPodInformer() since the pod informer
// already gets initial containers.
func WithInitialKubernetesContainers(nodeName string) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		k8sClient, err := NewK8sClient(nodeName)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}
		defer k8sClient.Close()

		containers, err := k8sClient.ListContainers()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		for _, container := range containers {
			// Make a copy instead of passing the same pointer at
			// each iteration of the loop
			newContainer := Container{}
			newContainer = container
			cc.initialContainers = append(cc.initialContainers,
				&newContainer)
		}
		return nil
	}
}

// WithPubSub enables subscription with container events with Subscribe().
// Optionally, a list of callbacks can be registered from the beginning, so
// they would get called for initial containers too.
func WithPubSub(funcs ...FuncNotify) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		if cc.pubsub == nil {
			cc.pubsub = NewGadgetPubSub()
		}
		for i, f := range funcs {
			cc.pubsub.Subscribe(fmt.Sprintf("WithPubSub/%d", i), f, nil)
		}
		return nil
	}
}

// getExpectedOwnerReference returns a resource only if it has an expected kind.
// In the case of multiple references, it first tries to find the controller
// reference. If there does not exist or it does not have an expected kind, the
// function will try to find the first resource with one of the expected
// resource kinds. Otherwise, it returns nil.
func getExpectedOwnerReference(ownerReferences []metav1.OwnerReference) *metav1.OwnerReference {
	// From: https://kubernetes.io/docs/concepts/workloads/controllers/
	// Notice that any change on this map needs to be aligned with the gadget
	// cluster role.
	expectedResKinds := map[string]struct{}{
		"Deployment":            {},
		"ReplicaSet":            {},
		"StatefulSet":           {},
		"DaemonSet":             {},
		"Job":                   {},
		"CronJob":               {},
		"ReplicationController": {},
	}

	var ownerRef *metav1.OwnerReference

	for i, or := range ownerReferences {
		if _, ok := expectedResKinds[or.Kind]; !ok {
			continue
		}

		if or.Controller != nil && *or.Controller {
			// There is at most one controller reference per resource
			return &or
		}

		// Keep track of the first expected reference in case it will be needed
		if ownerRef == nil {
			ownerRef = &ownerReferences[i]
		}
	}

	return ownerRef
}

func getOwnerReferences(dynamicClient dynamic.Interface,
	resNamespace, resKind, resGroupVersion, resName string,
) ([]metav1.OwnerReference, error) {
	gv, err := schema.ParseGroupVersion(resGroupVersion)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s/%s groupVersion %s: %w",
			resNamespace, resName, resGroupVersion, err)
	}

	params := schema.GroupVersionResource{
		Group:    gv.Group,
		Version:  gv.Version,
		Resource: resKind,
	}

	res, err := dynamicClient.
		Resource(params).
		Namespace(resNamespace).
		Get(context.TODO(), resName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("cannot fetch %s/%s %s/%s: %w",
			resKind, resGroupVersion, resNamespace, resName, err)
	}

	return res.GetOwnerReferences(), nil
}

// WithKubernetesEnrichment automatically adds pod metadata
//
// ContainerCollection.Initialize(WithKubernetesEnrichment())
func WithKubernetesEnrichment(nodeName string, kubeconfig *rest.Config) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		if kubeconfig == nil {
			var err error
			kubeconfig, err = rest.InClusterConfig()
			if err != nil {
				return fmt.Errorf("couldn't get Kubernetes config: %w", err)
			}
		}
		clientset, err := kubernetes.NewForConfig(kubeconfig)
		if err != nil {
			return fmt.Errorf("couldn't get Kubernetes client: %w", err)
		}

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			if container.Podname != "" {
				return true
			}

			if container.CgroupV1 == "" && container.CgroupV2 == "" {
				log.Errorf("kubernetes enricher: cannot work without cgroup paths")
				return true
			}

			fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
			pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
				FieldSelector: fieldSelector,
			})
			if err != nil {
				log.Errorf("kubernetes enricher: cannot fetch pods: %s", err)
				return true
			}

			// Fill Kubernetes fields
			namespace := ""
			podname := ""
			podUID := ""
			containerName := ""
			labels := make(map[string]string)
			for _, pod := range pods.Items {
				uid := string(pod.ObjectMeta.UID)
				// check if this container is associated to this pod
				uidWithUnderscores := strings.ReplaceAll(uid, "-", "_")

				if !strings.Contains(container.CgroupV2, uidWithUnderscores) &&
					!strings.Contains(container.CgroupV2, uid) &&
					!strings.Contains(container.CgroupV1, uidWithUnderscores) &&
					!strings.Contains(container.CgroupV1, uid) {
					continue
				}

				namespace = pod.ObjectMeta.Namespace
				podname = pod.ObjectMeta.Name
				podUID = uid

				for k, v := range pod.ObjectMeta.Labels {
					labels[k] = v
				}

				containers := append([]v1.Container{}, pod.Spec.InitContainers...)
				containers = append(containers, pod.Spec.Containers...)

				for _, c := range containers {
					for _, m := range container.OciConfig.Mounts {
						pattern := fmt.Sprintf("pods/%s/containers/%s/", uid, c.Name)
						if strings.Contains(m.Source, pattern) {
							containerName = c.Name
							break
						}
					}
				}
			}

			container.Namespace = namespace
			container.Podname = podname
			container.PodUID = podUID
			container.Name = containerName
			container.Labels = labels

			// drop pause containers
			if container.Podname != "" && containerName == "" {
				return false
			}

			return true
		})
		return nil
	}
}

// WithRuncFanotify uses fanotify to detect when containers are created and add
// them in the ContainerCollection.
//
// ContainerCollection.Initialize(WithRuncFanotify())
func WithRuncFanotify() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		runcNotifier, err := runcfanotify.NewRuncNotifier(func(notif runcfanotify.ContainerEvent) {
			switch notif.Type {
			case runcfanotify.EventTypeAddContainer:
				container := &Container{
					ID:        notif.ContainerID,
					Pid:       notif.ContainerPID,
					OciConfig: notif.ContainerConfig,
				}
				cc.AddContainer(container)
			case runcfanotify.EventTypeRemoveContainer:
				cc.RemoveContainer(notif.ContainerID)
			}
		})
		if err != nil {
			return fmt.Errorf("cannot start runc fanotify: %w", err)
		}

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			runcNotifier.Close()
		})

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			err := runcNotifier.AddWatchContainerTermination(container.ID, int(container.Pid))
			if err != nil {
				log.Errorf("runc fanotify enricher: failed to watch container %s: %s", container.ID, err)
				return false
			}
			return true
		})
		return nil
	}
}

// WithCgroupEnrichment enables an enricher to add the cgroup metadata
func WithCgroupEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			pid := int(container.Pid)
			if pid == 0 {
				log.Errorf("cgroup enricher: failed to enrich container %s with pid zero", container.ID)
				return true
			}

			cgroupPathV1, cgroupPathV2, err := cgroups.GetCgroupPaths(pid)
			if err != nil {
				log.Errorf("cgroup enricher: failed to get cgroup paths on container %s: %s", container.ID, err)
				return true
			}
			cgroupPathV2WithMountpoint, _ := cgroups.CgroupPathV2AddMountpoint(cgroupPathV2)
			cgroupID, _ := cgroups.GetCgroupID(cgroupPathV2WithMountpoint)

			container.CgroupPath = cgroupPathV2WithMountpoint
			container.CgroupID = cgroupID
			container.CgroupV1 = cgroupPathV1
			container.CgroupV2 = cgroupPathV2
			return true
		})
		return nil
	}
}

// WithLinuxNamespaceEnrichment enables an enricher to add the namespaces metadata
func WithLinuxNamespaceEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			pid := int(container.Pid)
			if pid == 0 {
				log.Errorf("namespace enricher: failed to enrich container %s with pid zero", container.ID)
				return true
			}

			mntns, err := containerutils.GetMntNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get mnt namespace on container %s: %s", container.ID, err)
				return true
			}
			container.Mntns = mntns

			netns, err := containerutils.GetNetNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get net namespace on container %s: %s", container.ID, err)
				return true
			}
			container.Netns = netns
			container.HostNetwork = netns == netnsHost
			return true
		})
		return nil
	}
}

// WithOCIConfigEnrichment enriches container using provided OCI config
func WithOCIConfigEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			if container.OciConfig == nil || container.IsEnriched() {
				return true
			}

			resolver, err := ociannotations.NewResolverFromAnnotations(container.OciConfig.Annotations)
			// ignore if annotations aren't supported for runtime e.g docker
			if err != nil {
				log.Debugf("OCIConfig enricher: failed to initialize annotation resolver: %s", err)
				return true
			}

			// TODO: handle this once we support pod sandboxes via WithContainerRuntimeEnrichment
			// Issue: https://github.com/inspektor-gadget/inspektor-gadget/issues/1095
			if ct := resolver.ContainerType(container.OciConfig.Annotations); ct == "sandbox" {
				return false
			}

			// enrich the container
			container.Runtime = resolver.Runtime()
			if name := resolver.ContainerName(container.OciConfig.Annotations); name != "" {
				container.Name = name
			}
			if podName := resolver.PodName(container.OciConfig.Annotations); podName != "" {
				container.Podname = podName
			}
			if podNamespace := resolver.PodNamespace(container.OciConfig.Annotations); podNamespace != "" {
				container.Namespace = podNamespace
			}
			if podUID := resolver.PodUID(container.OciConfig.Annotations); podUID != "" {
				container.PodUID = podUID
			}

			return true
		})
		return nil
	}
}

func WithNodeName(nodeName string) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.nodeName = nodeName
		return nil
	}
}

type TracerCollection interface {
	TracerMapsUpdater() FuncNotify
}

// WithTracerCollection enables the interation between the TracerCollection and ContainerCollection
// packages. When this option is used:
// - A cache mechanism to keep containers after they are removed is enabled.
// - The tracer collection TracerMapsUpdater() receives notifications from containers created /
// removed.
func WithTracerCollection(tc TracerCollection) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		// 2 seconds should enough time for the tracer to read the event from the perf ring
		// buffer and enrich it after the container has been terminated.
		cc.cacheDelay = 2 * time.Second
		cc.cachedContainers = &sync.Map{}

		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			path := fmt.Sprintf("/proc/%d/ns/mnt", container.Pid)
			fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				log.Warnf("WithTracerCollection: failed to open mntns reference for container %s: %s",
					container.ID, err)
				return false
			}

			container.mntNsFd = fd
			return true
		})

		if cc.pubsub == nil {
			cc.pubsub = NewGadgetPubSub()
		}

		cc.pubsub.Subscribe("tracercollection", tc.TracerMapsUpdater(), nil)

		return nil
	}
}
