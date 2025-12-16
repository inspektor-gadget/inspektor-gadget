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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ParamContainerName               = "containername"
	ParamPodName                     = "podname"
	ParamNamespace                   = "namespace"
	ParamSelector                    = "selector"
	ParamK8sContainerName            = "k8s-containername"
	ParamK8sPodName                  = "k8s-podname"
	ParamK8sNamespace                = "k8s-namespace"
	ParamK8sSelector                 = "k8s-selector"
	ParamRuntimeContainerName        = "runtime-containername"
	ParamRuntimeContainerImageDigest = "runtime-containerimage-digest"
	ParamRuntimeContainerImageID     = "runtime-containerimage-id"
)

// NewContainerSelector creates a ContainerSelector from parameter values
func NewContainerSelector(params *params.Params) containercollection.ContainerSelector {
	labels := parseLabelsSelector(params.Get(ParamK8sSelector).AsStringSlice())

	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName:        params.Get(ParamRuntimeContainerName).AsString(),
			ContainerImageID:     params.Get(ParamRuntimeContainerImageID).AsString(),
			ContainerImageDigest: params.Get(ParamRuntimeContainerImageDigest).AsString(),
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
		Title:       "K8s Pod Name",
		Description: "Kubernetes pods to filter on. Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.K8SPodName,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	k8sNamespace := params.ParamDesc{
		Key:         ParamK8sNamespace,
		Title:       "K8s Namespace",
		Description: "Kubernetes namespaces to filter on. Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.K8SNamespace,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	k8sSelector := params.ParamDesc{
		Key:         ParamK8sSelector,
		Title:       "K8s Label Selector",
		Description: "Kubernetes Labels selector to filter on. Supports comma-separated list and exclusion using '!' (e.g. '!key=value' or 'key=!value').",
		ValueHint:   gadgets.K8SLabels,
		Validator:   labelSelectorValidator,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	k8sContainerNameParam := params.ParamDesc{
		Key:         ParamK8sContainerName,
		Title:       "K8s Container Name",
		Description: "Kubernetes container names to filter on. Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.K8SContainerName,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	runtimeContainerParam := params.ParamDesc{
		Key:         ParamRuntimeContainerName,
		Title:       "Runtime Container Name",
		Description: "runtime-assigned name container names to filter on (not the name defined in the pod spec). Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.LocalContainer,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	runtimeContainerImageDigestParam := params.ParamDesc{
		Key:         ParamRuntimeContainerImageDigest,
		Title:       "Runtime Container Image Digest",
		Description: "runtime-assigned container image digest to filter on. Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.LocalImageDigest,
		Tags:        []string{api.TagGroupDataFiltering},
	}
	runtimeContainerImageIDParam := params.ParamDesc{
		Key:         ParamRuntimeContainerImageID,
		Title:       "Runtime Container Image ID",
		Description: "runtime-assigned container image ID to filter on. Supports comma-separated list and exclusion using '!'.",
		ValueHint:   gadgets.LocalImageID,
		Tags:        []string{api.TagGroupDataFiltering},
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

	return params.ParamDescs{&k8sPodName, &k8sNamespace, &k8sSelector, &k8sContainerNameParam, &runtimeContainerParam, &runtimeContainerImageDigestParam, &runtimeContainerImageIDParam}
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
