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

package kubemanager

import (
	"strings"
	"testing"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// makeParams builds a minimal params set for KubeManager instance params
// with the given namespace filter and all-namespaces flag.
func makeParams(namespace string, allNamespaces bool) *params.Params {
	descs := append(common.GetContainerSelectorParams(true),
		&params.ParamDesc{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		})
	p := descs.ToParams()
	if namespace != "" {
		p.Get(common.ParamNamespace).Set(namespace)
	}
	if allNamespaces {
		p.Get(ParamAllNamespaces).Set("true")
	}
	return p
}

func TestNewContainerSelectorExcludeNamespaces(t *testing.T) {
	tests := []struct {
		name              string
		excludeNamespaces []string
		instanceNamespace string
		allNamespaces     bool
		container         containercollection.Container
		wantMatch         bool
	}{
		{
			name:      "no exclusions, container in any namespace matches",
			container: containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "default"}}},
			wantMatch: true,
		},
		{
			name:              "excluded namespace does not match",
			excludeNamespaces: []string{"kube-system"},
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "kube-system"}}},
			wantMatch:         false,
		},
		{
			name:              "non-excluded namespace still matches",
			excludeNamespaces: []string{"kube-system"},
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "default"}}},
			wantMatch:         true,
		},
		{
			name:              "multiple exclusions, excluded namespace does not match",
			excludeNamespaces: []string{"kube-system", "monitoring"},
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "monitoring"}}},
			wantMatch:         false,
		},
		{
			name:              "multiple exclusions, non-excluded namespace matches",
			excludeNamespaces: []string{"kube-system", "monitoring"},
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "default"}}},
			wantMatch:         true,
		},
		{
			name:              "instance namespace filter combined with exclusion: included and not excluded",
			excludeNamespaces: []string{"kube-system"},
			instanceNamespace: "default",
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "default"}}},
			wantMatch:         true,
		},
		{
			name:              "instance namespace filter combined with exclusion: not in included set",
			excludeNamespaces: []string{"kube-system"},
			instanceNamespace: "default",
			container:         containercollection.Container{K8s: containercollection.K8sMetadata{BasicK8sMetadata: eventtypes.BasicK8sMetadata{Namespace: "other"}}},
			wantMatch:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := &KubeManager{
				externalCollections: true,
				excludeNamespaces:   tt.excludeNamespaces,
			}
			p := makeParams(tt.instanceNamespace, tt.allNamespaces)
			sel := km.newContainerSelector(p)

			// Verify the exclusion is expressed with "!" prefixes in the namespace field.
			for _, ns := range tt.excludeNamespaces {
				if !strings.Contains(sel.K8s.Namespace, "!"+ns) {
					t.Errorf("expected namespace selector %q to contain '!%s'", sel.K8s.Namespace, ns)
				}
			}

			got := containercollection.ContainerSelectorMatches(&sel, &tt.container)
			if got != tt.wantMatch {
				t.Errorf("ContainerSelectorMatches() = %v, want %v (namespace selector: %q, container namespace: %q)",
					got, tt.wantMatch, sel.K8s.Namespace, tt.container.K8s.Namespace)
			}
		})
	}
}

func TestInitExcludeNamespaces(t *testing.T) {
	tests := []struct {
		name              string
		paramValue        string
		wantExcluded      []string
	}{
		{
			name:         "empty value results in no exclusions",
			paramValue:   "",
			wantExcluded: nil,
		},
		{
			name:         "single namespace",
			paramValue:   "kube-system",
			wantExcluded: []string{"kube-system"},
		},
		{
			name:         "multiple namespaces",
			paramValue:   "kube-system,monitoring",
			wantExcluded: []string{"kube-system", "monitoring"},
		},
		{
			name:         "extra commas are ignored",
			paramValue:   "kube-system,,monitoring",
			wantExcluded: []string{"kube-system", "monitoring"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			km := &KubeManager{externalCollections: true}

			globalDescs := (&KubeManager{}).GlobalParamDescs()
			globalParams := globalDescs.ToParams()
			if tt.paramValue != "" {
				globalParams.Get(ParamExcludeNamespaces).Set(tt.paramValue)
			}

			err := km.Init(globalParams)
			if err != nil {
				t.Fatalf("Init() error = %v", err)
			}

			if len(km.excludeNamespaces) != len(tt.wantExcluded) {
				t.Fatalf("excludeNamespaces = %v, want %v", km.excludeNamespaces, tt.wantExcluded)
			}
			for i, ns := range tt.wantExcluded {
				if km.excludeNamespaces[i] != ns {
					t.Errorf("excludeNamespaces[%d] = %q, want %q", i, km.excludeNamespaces[i], ns)
				}
			}
		})
	}
}
