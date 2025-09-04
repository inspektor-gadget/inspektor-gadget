// Copyright 2025 The Inspektor Gadget authors
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

package common

import (
	"fmt"
	"strings"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ParamContainerName        = "containername"
	ParamPodName              = "podname"
	ParamNamespace            = "namespace"
	ParamSelector             = "selector"
	ParamK8sContainerName     = "k8s-containername"
	ParamK8sPodName           = "k8s-podname"
	ParamK8sNamespace         = "k8s-namespace"
	ParamK8sSelector          = "k8s-selector"
	ParamRuntimeContainerName = "runtime-containername"
)

// NewContainerSelector creates a ContainerSelector from parameter values
func NewContainerSelector(params *params.Params) containercollection.ContainerSelector {
	labels := parseLabelsSelector(params.Get(ParamK8sSelector).AsStringSlice())

	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: params.Get(ParamRuntimeContainerName).AsString(),
		},
		K8s: containercollection.K8sSelector{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace:     params.Get(ParamK8sNamespace).AsString(),
				PodName:       params.Get(ParamK8sPodName).AsString(),
				ContainerName: params.Get(ParamK8sContainerName).AsString(),
				PodLabels:     labels,
			},
		},
	}

	return containerSelector
}

func parseLabelsSelector(selectorSlice []string) map[string]string {
	labels := make(map[string]string)
	for _, pair := range selectorSlice {
		kv := strings.Split(pair, "=")
		if len(kv) == 2 {
			labels[kv[0]] = kv[1]
		}
	}
	return labels
}

func GetContainerSelectorParams(isKubeManager bool) params.ParamDescs {
	k8sPodName := params.ParamDesc{
		Key:         ParamK8sPodName,
		Description: "Show only data from Kubernetes pods with that name",
		ValueHint:   gadgets.K8SPodName,
	}
	k8sNamespace := params.ParamDesc{
		Key:         ParamK8sNamespace,
		Description: "Show only data from pods in a given Kubernetes namespace",
		ValueHint:   gadgets.K8SNamespace,
	}
	k8sSelector := params.ParamDesc{
		Key:         ParamK8sSelector,
		Description: "Kubernetes Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
		ValueHint:   gadgets.K8SLabels,
		Validator:   labelSelectorValidator,
	}
	k8sContainerNameParam := params.ParamDesc{
		Key:         ParamK8sContainerName,
		Description: "Show data only from containers with the name defined in the pod spec",
		ValueHint:   gadgets.K8SContainerName,
	}
	runtimeContainerParam := params.ParamDesc{
		Key:         ParamRuntimeContainerName,
		Description: "Show data only from containers with the runtime-assigned name (not the name defined in the pod spec)",
		ValueHint:   gadgets.LocalContainer,
	}

	// For backward compatibility, we swap the main keys and alternative keys, ensuring
	// things like '--podname' (vs '--k8s-podname') or 'operator.KubeManager.podname' (vs 'operator.KubeManager.k8s-podname')
	// still work fine for older clients since alternative key requires client side support.
	// Perhaps we can revisit this in future releases and only add alternative
	// keys without swapping once we are sure this won't be breaking change
	// for clients (e.g. kubectl-gadget).
	//
	// Also, for ease of use e.g. allowing using '--podname' instead of
	// '--k8s-podname' we set alternative keys for k8s params in the case
	// of KubeManager and runtime params in the case of LocalManager since they
	// both work in context for Kubernetes and Container runtimes respectively.
	if isKubeManager {
		// setup keys/aliases for Kubernetes metadata params
		k8sPodName.Key = ParamPodName
		k8sPodName.AlternativeKey = ParamK8sPodName
		k8sPodName.Alias = "p"

		k8sNamespace.Key = ParamNamespace
		k8sNamespace.AlternativeKey = ParamK8sNamespace
		k8sNamespace.Alias = "n"

		k8sSelector.Key = ParamSelector
		k8sSelector.AlternativeKey = ParamK8sSelector
		k8sSelector.Alias = "l"

		k8sContainerNameParam.Key = ParamContainerName
		k8sContainerNameParam.AlternativeKey = ParamK8sContainerName
		k8sContainerNameParam.Alias = "c"
	} else {
		// setup keys/aliases for runtime metadata params
		runtimeContainerParam.Key = ParamContainerName
		runtimeContainerParam.AlternativeKey = ParamRuntimeContainerName
		runtimeContainerParam.Alias = "c"
	}

	return params.ParamDescs{&k8sPodName, &k8sNamespace, &k8sSelector, &k8sContainerNameParam, &runtimeContainerParam}
}

func labelSelectorValidator(value string) error {
	if value == "" {
		return nil
	}

	pairs := strings.Split(value, ",")
	for _, pair := range pairs {
		kv := strings.Split(pair, "=")
		if len(kv) != 2 {
			return fmt.Errorf("should be a comma-separated list of key-value pairs (key=value[,key=value,...])")
		}
	}

	return nil
}
