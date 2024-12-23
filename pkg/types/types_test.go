// Copyright 2024 The Inspektor Gadget authors
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

package types

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestK8sMetadataUnmarshal(t *testing.T) {
	input := `{"podLabels": "app=nginx,valid=yes"}`
	expected := &K8sMetadata{
		BasicK8sMetadata: BasicK8sMetadata{
			PodLabels: map[string]string{
				"app":   "nginx",
				"valid": "yes",
			},
		},
	}

	var actual K8sMetadata
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, expected.PodLabels, actual.PodLabels)
}

func TestK8sMetadataUnmarshalBadFormat(t *testing.T) {
	input := `{"podLabels": "app=nginx,foo:bar,valid=yes,invalid"}`
	err := json.Unmarshal([]byte(input), &K8sMetadata{})
	assert.Error(t, err)
}

func TestK8sMetadataUnmarshalBadFormat2(t *testing.T) {
	input := `{"podlabels":{"k8s-app":"kube-dns","kubernetes.io/cluster-service":"true","kubernetes.io/name":"CoreDNS"}}`
	expected := &K8sMetadata{
		BasicK8sMetadata: BasicK8sMetadata{
			PodLabels: map[string]string{
				"k8s-app":                       "kube-dns",
				"kubernetes.io/cluster-service": "true",
				"kubernetes.io/name":            "CoreDNS",
			},
		},
	}

	var actual K8sMetadata
	err := json.Unmarshal([]byte(input), &actual)

	assert.NoError(t, err)
	assert.Equal(t, expected.PodLabels, actual.PodLabels)
}
