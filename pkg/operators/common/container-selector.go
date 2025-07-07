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
				PodName:       params.Get(ParamPodName).AsString(),
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

func GetKubeManagerParams() params.ParamDescs {
	return append(getContainerSelectorParams(),
		&params.ParamDesc{
			Key:            ParamContainerName,
			AlternativeKey: ParamK8sContainerName,
			Alias:          "c",
			Description:    "Show data only from containers with the name defined in the pod spec",
			ValueHint:      gadgets.K8SContainerName,
		},
		&params.ParamDesc{
			Key:         ParamRuntimeContainerName,
			Description: "Show data only from containers with the runtime-assigned name (not the name defined in the pod spec)",
			ValueHint:   gadgets.LocalContainer,
		})
}

func GetLocalManagerParams() params.ParamDescs {
	return append(getContainerSelectorParams(),
		&params.ParamDesc{
			Key:            ParamContainerName,
			AlternativeKey: ParamRuntimeContainerName,
			Alias:          "c",
			Description:    "Show data only from containers with the runtime-assigned name (not the name defined in the pod spec)",
			ValueHint:      gadgets.LocalContainer,
		},
		&params.ParamDesc{
			Key:         ParamK8sContainerName,
			Description: "Show data only from containers with the name defined in the pod spec",
			ValueHint:   gadgets.K8SContainerName,
		})
}

func getContainerSelectorParams() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:            ParamPodName,
			AlternativeKey: ParamK8sPodName,
			Alias:          "p",
			Description:    "Show only data from pods with that name",
			ValueHint:      gadgets.K8SPodName,
		},
		{
			Key:            ParamNamespace,
			AlternativeKey: ParamK8sNamespace,
			Alias:          "n",
			Description:    "Show only data from pods in a given Kubernetes namespace",
			ValueHint:      gadgets.K8SNamespace,
		},
		{
			Key:            ParamSelector,
			AlternativeKey: ParamK8sSelector,
			Alias:          "l",
			Description:    "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
			ValueHint:      gadgets.K8SLabels,
			Validator:      labelSelectorValidator,
		},
	}
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
