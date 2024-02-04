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

package containercollection

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	kubeletconfig "k8s.io/kubernetes/pkg/kubelet/apis/config"
	kubeletconfigscheme "k8s.io/kubernetes/pkg/kubelet/apis/config/scheme"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
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

	kubeletConfig, err := getCurrentKubeletConfig(clientset, nodeName)
	if err != nil {
		return nil, fmt.Errorf("getting /configz %w", err)
	}
	socketPath, _ := strings.CutPrefix(kubeletConfig.ContainerRuntimeEndpoint, "unix:///")

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %w", err)
	}

	// Get a runtime client to talk to the container runtime handling pods in
	// this node.
	list := strings.SplitN(node.Status.NodeInfo.ContainerRuntimeVersion, "://", 2)
	runtimeClient, err := containerutils.NewContainerRuntimeClient(
		&containerutilsTypes.RuntimeConfig{
			Name:       types.String2RuntimeName(list[0]),
			SocketPath: socketPath,
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

// trimRuntimePrefix removes the runtime prefix from a container ID.
func trimRuntimePrefix(id string) string {
	parts := strings.SplitN(id, "//", 2)
	if len(parts) != 2 {
		return ""
	}

	return parts[1]
}

// GetNonRunningContainers returns the list of containers IDs that are not running.
func (k *K8sClient) GetNonRunningContainers(pod *v1.Pod) []string {
	ret := []string{}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID != "" && s.State.Running == nil {
			id := trimRuntimePrefix(s.ContainerID)
			if id == "" {
				continue
			}

			ret = append(ret, id)
		}
	}

	return ret
}

// GetRunningContainers returns a list of the containers of a given Pod that are running.
func (k *K8sClient) GetRunningContainers(pod *v1.Pod) []Container {
	containers := []Container{}

	labels := map[string]string{}
	for k, v := range pod.ObjectMeta.Labels {
		labels[k] = v
	}

	containerStatuses := append([]v1.ContainerStatus{}, pod.Status.InitContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.ContainerStatuses...)
	containerStatuses = append(containerStatuses, pod.Status.EphemeralContainerStatuses...)

	for _, s := range containerStatuses {
		if s.ContainerID == "" || s.State.Running == nil {
			continue
		}

		containerData, err := k.runtimeClient.GetContainerDetails(s.ContainerID)
		if err != nil {
			log.Warnf("Skip pod %s/%s: cannot find container (ID: %s): %v",
				pod.GetNamespace(), pod.GetName(), s.ContainerID, err)
			continue
		}

		pid := containerData.Pid
		if pid > math.MaxUint32 {
			log.Errorf("Container PID (%d) exceeds math.MaxUint32 (%d), skipping this container", pid, math.MaxUint32)
			continue
		}

		containerDef := Container{
			Runtime: RuntimeMetadata{
				BasicRuntimeMetadata: containerData.Runtime.BasicRuntimeMetadata,
			},
			Pid: uint32(pid),
			K8s: K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     pod.GetNamespace(),
					PodName:       pod.GetName(),
					ContainerName: s.Name,
				},
				PodLabels: labels,
			},
		}
		containers = append(containers, containerDef)
	}

	return containers
}

// ListContainers return a list of the current containers that are
// running in the node.
func (k *K8sClient) ListContainers() (arr []Container, err error) {
	// List pods
	pods, err := k.clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: k.fieldSelector,
	})
	if err != nil {
		return nil, err
	}

	for _, pod := range pods.Items {
		containers := k.GetRunningContainers(&pod)
		arr = append(arr, containers...)
	}
	return arr, nil
}

func getCurrentKubeletConfig(clientset *kubernetes.Clientset, nodeName string) (*kubeletconfig.KubeletConfiguration, error) {
	resp, err := clientset.CoreV1().RESTClient().Get().Resource("nodes").Name(nodeName).Suffix("proxy", "configz").DoRaw(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch /configz from %q", nodeName)
	}
	kubeCfg, err := decodeConfigz(resp)
	if err != nil {
		return nil, err
	}
	return kubeCfg, nil
}

func decodeConfigz(respBody []byte) (*kubeletconfig.KubeletConfiguration, error) {
	// This hack because /configz reports the following structure:
	// {"kubeletconfig": {the JSON representation of kubeletconfigv1beta1.KubeletConfiguration}}
	type configzWrapper struct {
		ComponentConfig kubeletconfigv1beta1.KubeletConfiguration `json:"kubeletconfig"`
	}

	configz := configzWrapper{}
	kubeCfg := kubeletconfig.KubeletConfiguration{}

	err := json.Unmarshal(respBody, &configz)
	if err != nil {
		return nil, err
	}

	scheme, _, err := kubeletconfigscheme.NewSchemeAndCodecs()
	if err != nil {
		return nil, err
	}
	err = scheme.Convert(&configz.ComponentConfig, &kubeCfg, nil)
	if err != nil {
		return nil, err
	}

	return &kubeCfg, nil
}
