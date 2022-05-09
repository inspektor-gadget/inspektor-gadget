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

package k8s

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	containerutils "github.com/kinvolk/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	runtimeClient runtimeclient.ContainerRuntimeClient
}

func NewK8sClient(nodeName string) (*K8sClient, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", nodeName).String()

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %w", err)
	}

	// Get a runtime client to talk to the container runtime handling pods in
	// this node.
	list := strings.SplitN(node.Status.NodeInfo.ContainerRuntimeVersion, "://", 2)
	runtimeClient, err := containerutils.NewContainerRuntimeClient(
		&containerutils.RuntimeConfig{
			Name: list[0],
		})
	if err != nil {
		return nil, err
	}

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		runtimeClient: runtimeClient,
	}, nil
}

func (k *K8sClient) Close() {
	k.runtimeClient.Close()
}

// GetNonRunningContainers returns the list of containers IDs that are not running.
func (k *K8sClient) GetNonRunningContainers(pod *v1.Pod) []string {
	ret := []string{}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID != "" && s.State.Running == nil {
			ret = append(ret, s.ContainerID)
		}
	}

	return ret
}

// PodToContainers returns a list of the containers of a given Pod.
// Containers that are not running or don't have an ID are not considered.
func (k *K8sClient) PodToContainers(pod *v1.Pod) []pb.ContainerDefinition {
	containers := []pb.ContainerDefinition{}

	labels := []*pb.Label{}
	for k, v := range pod.ObjectMeta.Labels {
		labels = append(labels, &pb.Label{Key: k, Value: v})
	}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID == "" || s.State.Running == nil {
			continue
		}

		pid, err := k.runtimeClient.PidFromContainerID(s.ContainerID)
		if err != nil {
			log.Warnf("Skip pod %s/%s: cannot find pid: %v", pod.GetNamespace(), pod.GetName(), err)
			continue
		}

		idParts := strings.SplitN(s.ContainerID, "//", 2)
		if len(idParts) != 2 {
			continue
		}

		containerDef := pb.ContainerDefinition{
			Id:        idParts[1],
			Namespace: pod.GetNamespace(),
			Podname:   pod.GetName(),
			Name:      s.Name,
			Labels:    labels,
			Pid:       uint32(pid),
		}
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *K8sClient) ListContainers() (arr []pb.ContainerDefinition, err error) {
	// List pods
	pods, err := k.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		containers := k.PodToContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}
