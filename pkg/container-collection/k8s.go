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
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	securejoin "github.com/cyphar/filepath-securejoin"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/config/gadgettracermanagerconfig"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type K8sClient struct {
	clientset     *kubernetes.Clientset
	nodeName      string
	fieldSelector string
	runtimeClient runtimeclient.ContainerRuntimeClient
	RuntimeConfig *containerutilsTypes.RuntimeConfig
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

	socketPath, err := getContainerRuntimeSocketPath(clientset, nodeName)
	if err != nil {
		log.Warnf("Failed to retrieve socket path for runtime client from kubelet: %v. Falling back to default container runtime", err)
	} else {
		socketPath, err = securejoin.SecureJoin(host.HostRoot, socketPath)
		if err != nil {
			log.Warnf("securejoin failed: %s. Falling back to default container runtime", err)
		}
	}

	node, err := clientset.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("getting node %w", err)
	}

	// Get a runtime client to talk to the container runtime handling pods in
	// this node.
	list := strings.SplitN(node.Status.NodeInfo.ContainerRuntimeVersion, "://", 2)
	if socketPath == "" {
		socketPath, err = getSocketPathFromConfig(types.String2RuntimeName(list[0]))
		if err != nil {
			log.Warnf("Failed to retrieve socket path for runtime client from config: %v. Falling back to default container runtime", err)
		}
	}
	runtimeConfig := &containerutilsTypes.RuntimeConfig{
		Name:            types.String2RuntimeName(list[0]),
		SocketPath:      socketPath,
		RuntimeProtocol: containerutilsTypes.RuntimeProtocolCRI,
	}
	runtimeClient, err := containerutils.NewContainerRuntimeClient(runtimeConfig)
	if err != nil {
		return nil, err
	}

	return &K8sClient{
		clientset:     clientset,
		nodeName:      nodeName,
		fieldSelector: fieldSelector,
		runtimeClient: runtimeClient,
		RuntimeConfig: runtimeConfig,
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

func getSocketPathFromConfig(runtime types.RuntimeName) (string, error) {
	switch runtime {
	case types.RuntimeNameDocker:
		return config.Config.GetString(gadgettracermanagerconfig.DockerSocketPath), nil
	case types.RuntimeNameContainerd:
		return config.Config.GetString(gadgettracermanagerconfig.ContainerdSocketPath), nil
	case types.RuntimeNameCrio:
		return config.Config.GetString(gadgettracermanagerconfig.CrioSocketPath), nil
	case types.RuntimeNamePodman:
		return config.Config.GetString(gadgettracermanagerconfig.PodmanSocketPath), nil
	}
	return "", fmt.Errorf("unsupported runtime: %s", runtime)
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
	for k, v := range pod.Labels {
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

		// Check if process exists. Better check now rather than fail later in the enrichment pipeline.
		containerPidPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid))
		_, err = os.Stat(containerPidPath)
		if os.IsNotExist(err) {
			log.Warnf("Skip pod %s/%s container %q (ID: %s, image: %s): PID %d doesn't exist",
				pod.GetNamespace(), pod.GetName(),
				containerData.Runtime.RuntimeName,
				containerData.Runtime.ContainerID,
				containerData.Runtime.ContainerImageName,
				pid)
			continue
		}

		containerDef := Container{
			Runtime: RuntimeMetadata{
				BasicRuntimeMetadata: types.BasicRuntimeMetadata{
					RuntimeName:          containerData.Runtime.RuntimeName,
					ContainerID:          containerData.Runtime.ContainerID,
					ContainerName:        containerData.Runtime.ContainerName,
					ContainerPID:         uint32(pid),
					ContainerImageName:   containerData.Runtime.ContainerImageName,
					ContainerImageDigest: containerData.Runtime.ContainerImageDigest,
					ContainerStartedAt:   containerData.Runtime.ContainerStartedAt,
				},
			},
			K8s: K8sMetadata{
				BasicK8sMetadata: types.BasicK8sMetadata{
					Namespace:     pod.GetNamespace(),
					PodName:       pod.GetName(),
					ContainerName: s.Name,
					PodLabels:     labels,
				},
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

func getContainerRuntimeSocketPath(clientset *kubernetes.Clientset, nodeName string) (string, error) {
	kubeletConfig, err := getCurrentKubeletConfig(clientset, nodeName)
	if err != nil {
		return "", fmt.Errorf("getting /configz: %w", err)
	}

	socketPath := strings.TrimPrefix(kubeletConfig.ContainerRuntimeEndpoint, "unix://")
	if socketPath == "" {
		return "", fmt.Errorf("container runtime socket path is empty")
	}

	log.Infof("using the detected container runtime socket path from Kubelet's config: %s", socketPath)
	return socketPath, nil
}

// The /configz endpoint isn't officially documented. It was introduced in Kubernetes 1.26 and been around for a long time
// as stated in https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/component-base/configz/OWNERS
func getCurrentKubeletConfig(clientset *kubernetes.Clientset, nodeName string) (*kubeletconfigv1beta1.KubeletConfiguration, error) {
	resp, err := clientset.CoreV1().RESTClient().Get().Resource("nodes").
		Name(nodeName).Suffix("proxy", "configz").DoRaw(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("fetching /configz from %q: %w", nodeName, err)
	}
	kubeCfg, err := decodeConfigz(resp)
	if err != nil {
		return nil, err
	}
	return kubeCfg, nil
}

// Decodes the http response from /configz and returns the kubelet configuration
func decodeConfigz(respBody []byte) (*kubeletconfigv1beta1.KubeletConfiguration, error) {
	// This hack because /configz reports the following structure:
	// {"kubeletconfig": {the JSON representation of kubeletconfigv1beta1.KubeletConfiguration}}
	type configzWrapper struct {
		ComponentConfig kubeletconfigv1beta1.KubeletConfiguration `json:"kubeletconfig"`
	}

	configz := configzWrapper{}
	err := json.Unmarshal(respBody, &configz)
	if err != nil {
		return nil, err
	}

	return &configz.ComponentConfig, nil
}
