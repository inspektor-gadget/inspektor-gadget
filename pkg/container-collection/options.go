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
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cri"
	ociannotations "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/oci-annotations"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func setIfEmptyStr[T ~string](s *T, v T) {
	if *s == "" {
		*s = v
	}
}

func enrichContainerWithContainerData(containerData *runtimeclient.ContainerData, container *Container) {
	// Runtime
	setIfEmptyStr(&container.Runtime.ContainerID, containerData.Runtime.ContainerID)
	setIfEmptyStr(&container.Runtime.RuntimeName, containerData.Runtime.RuntimeName)
	setIfEmptyStr(&container.Runtime.ContainerName, containerData.Runtime.ContainerName)
	setIfEmptyStr(&container.Runtime.ContainerImageName, containerData.Runtime.ContainerImageName)
	setIfEmptyStr(&container.Runtime.ContainerImageDigest, containerData.Runtime.ContainerImageDigest)

	// Kubernetes
	setIfEmptyStr(&container.K8s.Namespace, containerData.K8s.Namespace)
	setIfEmptyStr(&container.K8s.PodName, containerData.K8s.PodName)
	setIfEmptyStr(&container.K8s.PodUID, containerData.K8s.PodUID)
	setIfEmptyStr(&container.K8s.ContainerName, containerData.K8s.ContainerName)
	if container.K8s.PodLabels == nil {
		container.SetPodLabels(containerData.K8s.PodLabels)
	}
}

func containerRuntimeEnricher(
	runtimeName types.RuntimeName,
	runtimeClient runtimeclient.ContainerRuntimeClient,
	container *Container,
) bool {
	// If the container is already enriched with all the metadata a runtime
	// client is able to provide, skip it.
	if runtimeclient.IsEnrichedWithK8sMetadata(container.K8s.BasicK8sMetadata) &&
		runtimeclient.IsEnrichedWithRuntimeMetadata(container.Runtime.BasicRuntimeMetadata) {
		return true
	}

	// For new CRI-O containers, the next GetContainer() call will always fail
	// because the container doesn't exist yet. So, if we have the sandbox ID,
	// let's enrich the container at least with the PodLabels as the PodSandbox
	// do exist at this point.
	if container.Runtime.RuntimeName == types.RuntimeNameCrio {
		criClient, ok := runtimeClient.(*cri.CRIClient)
		if ok && container.SandboxId != "" {
			labels, err := criClient.GetPodLabels(container.SandboxId)
			if err != nil {
				log.Warnf("Runtime enricher (%s): failed to GetPodLabels: %s",
					runtimeName, err)

				// We couldn't get the labels, but don't drop the container.
				return true
			}
			container.SetPodLabels(labels)
		}

		return true
	}

	containerData, err := runtimeClient.GetContainer(container.Runtime.ContainerID)
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

// WithDisableContainerRuntimeWarnings disables the warnings about container runtime.
func WithDisableContainerRuntimeWarnings() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.disableContainerRuntimeWarnings = true
		return nil
	}
}

// WithMultipleContainerRuntimesEnrichment is a wrapper for
// WithContainerRuntimeEnrichment() to allow caller to add multiple runtimes in
// one single call.
//
// ContainerCollection.Initialize(WithMultipleContainerRuntimesEnrichment([]*RuntimeConfig)...)
func WithMultipleContainerRuntimesEnrichment(runtimes []*containerutilsTypes.RuntimeConfig) ContainerCollectionOption {
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
func WithContainerRuntimeEnrichment(runtime *containerutilsTypes.RuntimeConfig) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		runtimeClient, err := containerutils.NewContainerRuntimeClient(runtime)
		if err != nil {
			if !cc.disableContainerRuntimeWarnings {
				log.Warnf("Runtime enricher (%s): failed to initialize container runtime: %s",
					runtime.Name, err)
			}
			return err
		}

		switch runtime.Name {
		case types.RuntimeNamePodman:
			// Podman only supports runtime enrichment for initial containers otherwise it will deadlock.
			// As a consequence, we need to ensure that new podman containers will be enriched with all
			// the information via other enrichers e.g. see RuncNotifier.futureContainers implementation
			// to see how container name is enriched.
		default:
			// Add the enricher for future containers even if enriching the current
			// containers fails. We do it because the runtime could be temporarily
			// unavailable and once it is up, we will start receiving the
			// notifications for its containers thus we will be able to enrich them.
			cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
				return containerRuntimeEnricher(runtime.Name, runtimeClient, container)
			})
		}

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			if err := runtimeClient.Close(); err != nil {
				log.Warnf("failed to close container runtime %s: %s", runtime.Name, err)
			}
		})

		// Enrich already running containers
		containers, err := runtimeClient.GetContainers()
		if err != nil {
			if !cc.disableContainerRuntimeWarnings {
				log.Warnf("Runtime enricher (%s): couldn't get current containers: %s",
					runtime.Name, err)
			}
			return nil
		}
		for _, container := range containers {
			if container.Runtime.State != runtimeclient.StateRunning {
				log.Debugf("Runtime enricher(%s): Skip container %q (ID: %s, image: %s): not running",
					runtime.Name, container.Runtime.ContainerName, container.Runtime.ContainerID,
					container.Runtime.ContainerImageName)
				continue
			}

			containerDetails, err := runtimeClient.GetContainerDetails(container.Runtime.ContainerID)
			if err != nil {
				log.Debugf("Runtime enricher (%s): Skip container %q (ID: %s, image: %s): couldn't find container: %s",
					runtime.Name, container.Runtime.ContainerName, container.Runtime.ContainerID,
					container.Runtime.ContainerImageName, err)
				continue
			}

			pid := containerDetails.Pid
			if pid > math.MaxUint32 {
				log.Errorf("Container PID (%d) exceeds math.MaxUint32 (%d), skipping this container", pid, math.MaxUint32)
				continue
			}

			// Check if process exists. Better check now rather than fail later in the enrichment pipeline.
			containerPidPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid))
			_, err = os.Stat(containerPidPath)
			if os.IsNotExist(err) {
				log.Warnf("Runtime enricher (%s): Skip container %q (ID: %s, image: %s): PID %d doesn't exist",
					runtime.Name, container.Runtime.ContainerName, container.Runtime.ContainerID, container.Runtime.ContainerImageName, pid)
				continue
			}

			var c Container
			c.Runtime.ContainerPID = uint32(pid)
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
			return fmt.Errorf("creating Kubernetes client: %w", err)
		}

		podInformer, err := NewPodInformer(nodeName)
		if err != nil {
			return fmt.Errorf("creating pod informer: %w", err)
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
				case key, ok := <-podInformer.DeletedChan():
					if !ok {
						return
					}
					if containerIDs, ok := containerIDsByKey[key]; ok {
						for containerID := range containerIDs {
							cc.RemoveContainer(containerID)
						}
					}
					delete(containerIDsByKey, key)
				case pod, ok := <-podInformer.UpdatedChan():
					if !ok {
						return
					}
					key, _ := cache.MetaNamespaceKeyFunc(pod)
					containerIDs, ok := containerIDsByKey[key]
					if !ok {
						containerIDs = make(map[string]struct{})
						containerIDsByKey[key] = containerIDs
					}

					// first: remove containers that are not running anymore
					nonrunning := k8sClient.GetNonRunningContainers(pod)
					for _, id := range nonrunning {
						// container had not been added, no need to remove it
						if _, ok := containerIDs[id]; !ok {
							continue
						}
						cc.RemoveContainer(id)
					}

					// second: add containers that are in running state
					containers := k8sClient.GetRunningContainers(pod)
					for _, container := range containers {
						// The container is already registered, there is not any chance the
						// PID will change, so ignore it.
						if _, ok := containerIDs[container.Runtime.ContainerID]; ok {
							continue
						}
						containerIDs[container.Runtime.ContainerID] = struct{}{}

						// Make a copy instead of passing the same pointer at
						// each iteration of the loop
						newContainer := Container{}
						newContainer = container
						if fallbackMode {
							if cc.GetContainer(container.Runtime.ContainerID) != nil {
								continue // container is already there. All good!
							}
							log.Warnf("container %s/%s/%s wasn't detected by the main hook! The fallback pod informer will add it.",
								container.K8s.Namespace, container.K8s.PodName, container.K8s.ContainerName)
						}
						cc.AddContainer(&newContainer)
					}
				}
			}
		}()

		return nil
	}
}

// WithHost adds the host as a virtual/fake container; TODO: Just for testing
func WithHost() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		newContainer := Container{}
		newContainer.K8s.ContainerName = "host"
		newContainer.CgroupID = 1
		newContainer.Runtime.ContainerPID = 1
		newContainer.HostNetwork = true
		cc.initialContainers = append(cc.initialContainers, &newContainer)
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
			return fmt.Errorf("creating Kubernetes client: %w", err)
		}
		defer k8sClient.Close()

		containers, err := k8sClient.ListContainers()
		if err != nil {
			return fmt.Errorf("listing containers: %w", err)
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
		return nil, fmt.Errorf("parsing %s/%s groupVersion %s: %w",
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
		return nil, fmt.Errorf("fetching %s/%s %s/%s: %w",
			resKind, resGroupVersion, resNamespace, resName, err)
	}

	return res.GetOwnerReferences(), nil
}

func getPodByCgroups(clientset *kubernetes.Clientset, nodeName string, container *Container) (*corev1.Pod, error) {
	if container.CgroupV1 == "" && container.CgroupV2 == "" {
		return nil, fmt.Errorf("need cgroup paths to work")
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fieldSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching pods: %w", err)
	}

	for _, pod := range pods.Items {
		uid := string(pod.UID)
		// check if this container is associated to this pod
		uidWithUnderscores := strings.ReplaceAll(uid, "-", "_")

		if !strings.Contains(container.CgroupV2, uidWithUnderscores) &&
			!strings.Contains(container.CgroupV2, uid) &&
			!strings.Contains(container.CgroupV1, uidWithUnderscores) &&
			!strings.Contains(container.CgroupV1, uid) {
			continue
		}
		return &pod, nil
	}
	return nil, fmt.Errorf("no pod found for container %q", container.Runtime.ContainerName)
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
				return fmt.Errorf("getting Kubernetes config: %w", err)
			}
		}
		clientset, err := kubernetes.NewForConfig(kubeconfig)
		if err != nil {
			return fmt.Errorf("getting Kubernetes client: %w", err)
		}

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			// Skip enriching if basic k8s fields are already known.
			// This is an optimization and to make sure to avoid erasing the fields in case of error.
			if !runtimeclient.IsEnrichedWithK8sMetadata(container.K8s.BasicK8sMetadata) {
				var pod *corev1.Pod
				var err error
				if container.K8s.PodName == "" || container.K8s.Namespace == "" {
					pod, err = getPodByCgroups(clientset, nodeName, container)
					if err != nil {
						log.Errorf("kubernetes enricher (from UID): cannot find pod for container %s: %s", container.Runtime.ContainerName, err)
						return false
					}
				} else {
					pod, err = clientset.CoreV1().Pods(container.K8s.Namespace).Get(context.TODO(), container.K8s.PodName, metav1.GetOptions{})
					if err != nil {
						log.Errorf("kubernetes enricher (from ns/podname): cannot find pod %s/%s: %s", container.K8s.Namespace, container.K8s.PodName, err)
						return false
					}
				}

				if container.K8s.ContainerName == "" {
					var containerName string
					uid := string(pod.UID)
					containerNames := []string{}
					for _, c := range pod.Spec.Containers {
						containerNames = append(containerNames, c.Name)
					}
					for _, c := range pod.Spec.InitContainers {
						containerNames = append(containerNames, c.Name)
					}
					for _, c := range pod.Spec.EphemeralContainers {
						containerNames = append(containerNames, c.Name)
					}
				outerLoop:
					for _, name := range containerNames {
						for _, m := range container.OciConfig.Mounts {
							pattern := fmt.Sprintf("pods/%s/containers/%s/", uid, name)
							if strings.Contains(m.Source, pattern) {
								containerName = name
								break outerLoop
							}
						}
					}
					container.K8s.ContainerName = containerName
				}

				container.K8s.Namespace = pod.Namespace
				container.K8s.PodName = pod.Name
				container.K8s.PodUID = string(pod.UID)
				container.SetPodLabels(pod.Labels)

				// drop pause containers
				if container.K8s.PodName != "" && container.K8s.ContainerName == "" {
					return false
				}
			}

			if container.K8s.ownerReference == nil {
				_, err = container.GetOwnerReference()
				if err != nil {
					log.Errorf("kubernetes enricher: failed to get owner reference for container %s: %s", container.Runtime.ContainerID, err)
					// Don't drop the container. We just have problems getting the owner reference, but still want to trace the container.
				}
			}
			return true
		})
		return nil
	}
}

// WithContainerFanotifyEbpf uses fanotify and eBPF to detect when containers
// are created and add them in the ContainerCollection.
//
// This works either in the host pid namespace or in a container pid namespace.
//
// ContainerCollection.Initialize(WithContainerFanotifyEbpf())
func WithContainerFanotifyEbpf() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		containerNotifier, err := containerhook.NewContainerNotifier(func(notif containerhook.ContainerEvent) {
			switch notif.Type {
			case containerhook.EventTypeAddContainer:
				container := &Container{
					Runtime: RuntimeMetadata{
						BasicRuntimeMetadata: types.BasicRuntimeMetadata{
							ContainerID:   notif.ContainerID,
							ContainerPID:  notif.ContainerPID,
							ContainerName: notif.ContainerName,
						},
					},
					OciConfig: notif.ContainerConfig,
				}
				cc.AddContainer(container)
			case containerhook.EventTypeRemoveContainer:
				cc.RemoveContainer(notif.ContainerID)
			}
		})
		if err != nil {
			return fmt.Errorf("starting container fanotify: %w", err)
		}

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			containerNotifier.Close()
		})

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			err := containerNotifier.AddWatchContainerTermination(container.Runtime.ContainerID, int(container.ContainerPid()))
			if err != nil {
				log.Errorf("container fanotify enricher: failed to watch container %s: %s", container.Runtime.ContainerID, err)
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
			pid := int(container.ContainerPid())
			if pid == 0 {
				log.Errorf("cgroup enricher: failed to enrich container %s with pid zero", container.Runtime.ContainerID)
				return true
			}

			cgroupPathV1, cgroupPathV2, err := cgroups.GetCgroupPaths(pid)
			if err != nil {
				log.Errorf("cgroup enricher: failed to get cgroup paths on container %s: %s", container.Runtime.ContainerID, err)
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
		// GetNetNs() needs a pid in the host pid namespace: it uses $HOST_ROOT/proc/$pid/ns/net
		// This needs CAP_SYS_PTRACE.
		netnsHost, err := containerutils.GetNetNs(1)
		if err != nil {
			return fmt.Errorf("getting host net ns inode: %w", err)
		}

		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			pid := int(container.ContainerPid())
			if pid == 0 {
				log.Errorf("namespace enricher: failed to enrich container %s with pid zero", container.Runtime.ContainerID)
				return true
			}

			mntns, err := containerutils.GetMntNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get mnt namespace on container %s: %s", container.Runtime.ContainerID, err)
				return true
			}
			container.Mntns = mntns

			netns, err := containerutils.GetNetNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get net namespace on container %s: %s", container.Runtime.ContainerID, err)
				return true
			}
			container.Netns = netns
			container.HostNetwork = netns == netnsHost
			return true
		})
		return nil
	}
}

// isEnrichedWithOCIConfigInfo returns true if container is enriched with the
// metadata from OCI config that WithOCIConfigEnrichment is able to provide.
// Keep in sync with what WithOCIConfigEnrichment does.
func isEnrichedWithOCIConfigInfo(container *Container) bool {
	return container.OciConfig != nil &&
		container.Runtime.RuntimeName != "" &&
		container.Runtime.ContainerImageName != "" &&
		container.K8s.ContainerName != "" &&
		container.K8s.PodName != "" &&
		container.K8s.Namespace != "" &&
		container.K8s.PodUID != "" &&
		container.SandboxId != ""
}

// WithOCIConfigEnrichment enriches container using provided OCI config
func WithOCIConfigEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			if container.OciConfig == nil || isEnrichedWithOCIConfigInfo(container) {
				return true
			}

			if cm, ok := container.OciConfig.Annotations["io.container.manager"]; ok && cm == "libpod" {
				container.Runtime.RuntimeName = types.RuntimeNamePodman
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

			// Enrich the container. Keep in sync with isEnrichedWithOCIConfigInfo.
			container.Runtime.RuntimeName = resolver.Runtime()
			if name := resolver.ContainerName(container.OciConfig.Annotations); name != "" {
				container.K8s.ContainerName = name
			}
			if podName := resolver.PodName(container.OciConfig.Annotations); podName != "" {
				container.K8s.PodName = podName
			}
			if podNamespace := resolver.PodNamespace(container.OciConfig.Annotations); podNamespace != "" {
				container.K8s.Namespace = podNamespace
			}
			if podUID := resolver.PodUID(container.OciConfig.Annotations); podUID != "" {
				container.K8s.PodUID = podUID
			}
			if imageName := resolver.ContainerImageName(container.OciConfig.Annotations); imageName != "" {
				container.Runtime.ContainerImageName = imageName
			}
			if podSandboxId := resolver.PodSandboxId(container.OciConfig.Annotations); podSandboxId != "" {
				container.SandboxId = podSandboxId
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

		// This functions cleans up the container cache
		go func() {
			ticker := time.NewTicker(5 * time.Second)

			for {
				select {
				case <-ticker.C:
					cc.mu.Lock()

					if cc.closed {
						cc.mu.Unlock()
						return
					}

					now := time.Now()

					cc.cachedContainers.Range(func(key, value interface{}) bool {
						c := value.(*Container)

						if now.Sub(c.deletionTimestamp) > cc.cacheDelay {
							c.close()
							cc.cachedContainers.Delete(c.Runtime.ContainerID)
						}

						return true
					})

					cc.mu.Unlock()
				case <-cc.done:
					return
				}
			}
		}()

		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			mntNsPath := filepath.Join(host.HostProcFs, fmt.Sprint(container.ContainerPid()), "ns", "mnt")
			mntNsFd, err := unix.Open(mntNsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				log.Warnf("WithTracerCollection: failed to open mntns reference for container %s: %s",
					container.Runtime.ContainerID, err)
				return false
			}
			if container.mntNsFd != 0 {
				log.Warnf("WithTracerCollection: mntns reference already set for container %s", container.Runtime.ContainerID)
			}
			container.mntNsFd = mntNsFd

			netNsPath := filepath.Join(host.HostProcFs, fmt.Sprint(container.ContainerPid()), "ns", "net")
			netNsFd, err := unix.Open(netNsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				log.Warnf("WithTracerCollection: failed to open netns reference for container %s: %s",
					container.Runtime.ContainerID, err)
				return false
			}
			if container.netNsFd != 0 {
				log.Warnf("WithTracerCollection: netns reference already set for container %s", container.Runtime.ContainerID)
			}
			container.netNsFd = netNsFd
			return true
		})

		cc.cleanUpFuncs = append(cc.cleanUpFuncs, func() {
			// clean up functions are called with the mutex held
			cc.cachedContainers.Range(func(key, value interface{}) bool {
				c := value.(*Container)
				c.close()
				cc.cachedContainers.Delete(key)
				return true
			})
		})

		if cc.pubsub == nil {
			cc.pubsub = NewGadgetPubSub()
		}

		cc.pubsub.Subscribe("tracercollection", tc.TracerMapsUpdater(), nil)

		return nil
	}
}

// WithProcEnrichment enables an enricher to add process metadata
func WithProcEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *Container) bool {
			pid := int(container.ContainerPid())
			if pid == 0 {
				log.Errorf("proc enricher: failed to enrich container %s with pid zero", container.Runtime.ContainerID)
				return false
			}

			procStat, err := host.GetProcStat(pid)
			if err != nil {
				log.Errorf("proc enricher: failed to read /proc/%d/stat for container %s: %v", pid, container.Runtime.ContainerID, err)
				return false
			}

			container.Runtime.ContainerStartedAt = procStat.StartedAt
			return true
		})
		return nil
	}
}
