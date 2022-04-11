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
	"fmt"
	"strings"

	dockertypes "github.com/docker/docker/api/types"
	dockerfilters "github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/k8s"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
)

// WithDockerEnrichment automatically adds container metadata with Docker
//
// ContainerCollection.ContainerCollectionInitialize(WithDockerEnrichment())
func WithDockerEnrichment() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		dockercli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv)
		if err != nil {
			return err
		}

		// Already running containers
		containers, err := dockercli.ContainerList(context.Background(),
			dockertypes.ContainerListOptions{
				All: true,
			})
		if err != nil {
			return err
		}
		for _, container := range containers {
			res, err := dockercli.ContainerInspect(context.Background(), container.ID)
			if err != nil {
				log.Errorf("failed to inspect container %s: %s", container.ID, err)
				continue
			}
			if !res.State.Running {
				continue
			}
			if res.State.Pid == 0 {
				log.Errorf("failed to inspect container %s: container pid is 0", container.ID)
				continue
			}
			pid := res.State.Pid
			cc.initialContainers = append(cc.initialContainers,
				&pb.ContainerDefinition{
					Id:  container.ID,
					Pid: uint32(pid),
				})
		}

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *pb.ContainerDefinition) bool {
			filter := dockerfilters.NewArgs()
			filter.Add("id", container.Id)
			containers, err := dockercli.ContainerList(context.Background(),
				dockertypes.ContainerListOptions{
					All:     true,
					Filters: filter,
				})
			if err != nil {
				log.Errorf("failed to list container %s: %s", container.Id, err)
				return true
			}
			if len(containers) == 1 {
				if len(containers[0].Names) > 0 {
					container.Name = strings.TrimPrefix(containers[0].Names[0], "/")
					// Some gadgets require the namespace and pod name to be set
					container.Namespace = "default"
					container.Podname = container.Name
				}
			} else {
				log.Errorf("container %s has %d names", container.Id, len(containers))
			}
			return true
		})
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
		k8sClient, err := k8s.NewK8sClient(nodeName)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}

		createdChan := make(chan *v1.Pod)
		deletedChan := make(chan string)

		_, err = k8s.NewPodInformer(nodeName, createdChan, deletedChan)
		if err != nil {
			return fmt.Errorf("failed to create pod informer: %w", err)
		}

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
				case d := <-deletedChan:
					if containerIDs, ok := containerIDsByKey[d]; ok {
						for containerID := range containerIDs {
							cc.RemoveContainer(containerID)
						}
					}
				case c := <-createdChan:
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
						if _, ok := containerIDs[container.Id]; ok {
							continue
						}

						// Make a copy instead of passing the same pointer at
						// each iteration of the loop
						newContainer := pb.ContainerDefinition{}
						newContainer = container
						if fallbackMode {
							if cc.GetContainer(container.Id) != nil {
								continue // container is already there. All good!
							}
							log.Warnf("container %s/%s/%s wasn't detected by the main hook! The fallback pod informer will add it.",
								container.Namespace, container.Podname, container.Name)
						}
						cc.AddContainer(&newContainer)

						containerIDs[container.Id] = struct{}{}
					}
				}
			}
			// TODO: ContainerCollection does not have a Stop() method
			// podInformer.Stop()
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
		k8sClient, err := k8s.NewK8sClient(nodeName)
		if err != nil {
			return fmt.Errorf("failed to create Kubernetes client: %w", err)
		}

		containers, err := k8sClient.ListContainers()
		if err != nil {
			return fmt.Errorf("failed to list containers: %w", err)
		}

		for _, container := range containers {
			// Make a copy instead of passing the same pointer at
			// each iteration of the loop
			newContainer := pb.ContainerDefinition{}
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
func WithPubSub(funcs ...pubsub.FuncNotify) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		if cc.pubsub == nil {
			cc.pubsub = pubsub.NewGadgetPubSub()
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

func getKubeClientDynamic() (dynamic.Interface, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("couldn't get Kubernetes config: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("couldn't create dynamic Kubernetes client: %w", err)
	}
	return dynamicClient, nil
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

func ownerReferenceEnrichment(
	containerDefinition *pb.ContainerDefinition,
	ownerReferences []metav1.OwnerReference,
) error {
	if containerDefinition.OwnerReference != nil {
		// Already set. Do nothing
		return nil
	}

	dynamicClient, err := getKubeClientDynamic()
	if err != nil {
		return fmt.Errorf("failed to get dynamic Kubernetes client: %w", err)
	}

	resGroupVersion := "v1"
	resKind := "pods"
	resName := containerDefinition.Podname
	resNamespace := containerDefinition.Namespace

	var highestOwnerRef *metav1.OwnerReference

	// Iterate until we reach the highest level of reference with one of the
	// expected resource kind. Take into account that if this logic is changed,
	// the gadget cluster role needs to be updated accordingly.
	for {
		if len(ownerReferences) == 0 {
			ownerReferences, err = getOwnerReferences(dynamicClient,
				resNamespace, resKind, resGroupVersion, resName)
			if err != nil {
				return fmt.Errorf("failed to get %s/%s/%s/%s owner reference: %w",
					resNamespace, resKind, resGroupVersion, resName, err)
			}

			// No owner reference found
			if len(ownerReferences) == 0 {
				break
			}
		}

		ownerRef := getExpectedOwnerReference(ownerReferences)
		if ownerRef == nil {
			// None expected owner reference found
			break
		}

		// Update parameters for next iteration (Namespace does not change)
		highestOwnerRef = ownerRef
		resGroupVersion = ownerRef.APIVersion
		resKind = strings.ToLower(ownerRef.Kind) + "s"
		resName = ownerRef.Name
		ownerReferences = nil
	}

	// Update container's owner reference (If any)
	if highestOwnerRef != nil {
		containerDefinition.OwnerReference = &pb.OwnerReference{
			Apiversion: highestOwnerRef.APIVersion,
			Kind:       highestOwnerRef.Kind,
			Name:       highestOwnerRef.Name,
			Uid:        string(highestOwnerRef.UID),
		}
	}

	return nil
}

// WithKubernetesEnrichment automatically adds pod metadata
//
// ContainerCollection.ContainerCollectionInitialize(WithKubernetesEnrichment())
func WithKubernetesEnrichment(nodeName string) ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		config, err := rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("cannot start Kubernetes client: %w", err)
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("cannot start Kubernetes client: %w", err)
		}

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(containerDefinition *pb.ContainerDefinition) bool {
			// Enrich only with owner reference if the data is already there
			if containerDefinition.Podname != "" {
				err := ownerReferenceEnrichment(containerDefinition, nil)
				if err != nil {
					log.Errorf("kubernetes enricher: Failed to enrich with owner reference: %s", err)
				}
				return true
			}

			if containerDefinition.CgroupV1 == "" && containerDefinition.CgroupV2 == "" {
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
			containerName := ""
			labels := []*pb.Label{}
			var podOwnerRef []metav1.OwnerReference
			for _, pod := range pods.Items {
				uid := string(pod.ObjectMeta.UID)
				// check if this container is associated to this pod
				uidWithUnderscores := strings.ReplaceAll(uid, "-", "_")

				if !strings.Contains(containerDefinition.CgroupV2, uidWithUnderscores) &&
					!strings.Contains(containerDefinition.CgroupV2, uid) &&
					!strings.Contains(containerDefinition.CgroupV1, uidWithUnderscores) &&
					!strings.Contains(containerDefinition.CgroupV1, uid) {
					continue
				}

				namespace = pod.ObjectMeta.Namespace
				podname = pod.ObjectMeta.Name

				for k, v := range pod.ObjectMeta.Labels {
					labels = append(labels, &pb.Label{Key: k, Value: v})
				}

				containers := append([]v1.Container{}, pod.Spec.InitContainers...)
				containers = append(containers, pod.Spec.Containers...)

				for _, container := range containers {
					for _, mountSource := range containerDefinition.MountSources {
						pattern := fmt.Sprintf("pods/%s/containers/%s/", uid, container.Name)
						if strings.Contains(mountSource, pattern) {
							containerName = container.Name

							// Keep track of the pod owner reference
							podOwnerRef = pod.GetOwnerReferences()
							break
						}
					}
				}
			}

			containerDefinition.Namespace = namespace
			containerDefinition.Podname = podname
			containerDefinition.Name = containerName
			containerDefinition.Labels = labels

			// drop pause containers
			if containerDefinition.Podname != "" && containerName == "" {
				return false
			}

			if len(podOwnerRef) != 0 {
				err := ownerReferenceEnrichment(containerDefinition, podOwnerRef)
				if err != nil {
					log.Errorf("kubernetes enricher: Failed to enrich with owner reference: %s", err)
				}
			}

			return true
		})
		return nil
	}
}

// WithRuncFanotify uses fanotify to detect when containers are created and add
// them in the ContainerCollection.
//
// ContainerCollection.ContainerCollectionInitialize(WithRuncFanotify())
func WithRuncFanotify() ContainerCollectionOption {
	return func(cc *ContainerCollection) error {
		runcNotifier, err := runcfanotify.NewRuncNotifier(func(notif runcfanotify.ContainerEvent) {
			switch notif.Type {
			case runcfanotify.EventTypeAddContainer:
				mountSources := []string{}
				for _, m := range notif.ContainerConfig.Mounts {
					mountSources = append(mountSources, m.Source)
				}
				containerDefinition := &pb.ContainerDefinition{
					Id:           notif.ContainerID,
					Pid:          notif.ContainerPID,
					MountSources: mountSources,
				}

				cc.AddContainer(containerDefinition)
			case runcfanotify.EventTypeRemoveContainer:
				cc.RemoveContainer(notif.ContainerID)
			}
		})
		if err != nil {
			return fmt.Errorf("cannot start runc fanotify: %w", err)
		}

		// Future containers
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *pb.ContainerDefinition) bool {
			err := runcNotifier.AddWatchContainerTermination(container.Id, int(container.Pid))
			if err != nil {
				log.Errorf("runc fanotify enricher: failed to watch container %s: %s", container.Id, err)
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
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *pb.ContainerDefinition) bool {
			pid := int(container.Pid)
			if pid == 0 {
				log.Errorf("cgroup enricher: failed to enrich container %s with pid zero", container.Id)
				return true
			}

			cgroupPathV1, cgroupPathV2, err := containerutils.GetCgroupPaths(pid)
			if err != nil {
				log.Errorf("cgroup enricher: failed to get cgroup paths on container %s: %s", container.Id, err)
				return true
			}
			cgroupPathV2WithMountpoint, _ := containerutils.CgroupPathV2AddMountpoint(cgroupPathV2)
			cgroupID, _ := containerutils.GetCgroupID(cgroupPathV2WithMountpoint)

			container.CgroupPath = cgroupPathV2WithMountpoint
			container.CgroupId = cgroupID
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
		cc.containerEnrichers = append(cc.containerEnrichers, func(container *pb.ContainerDefinition) bool {
			pid := int(container.Pid)
			if pid == 0 {
				log.Errorf("namespace enricher: failed to enrich container %s with pid zero", container.Id)
				return true
			}

			mntns, err := containerutils.GetMntNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get mnt namespace on container %s: %s", container.Id, err)
				return true
			}
			container.Mntns = mntns

			netns, err := containerutils.GetNetNs(pid)
			if err != nil {
				log.Errorf("namespace enricher: failed to get net namespace on container %s: %s", container.Id, err)
				return true
			}
			container.Netns = netns
			return true
		})
		return nil
	}
}
