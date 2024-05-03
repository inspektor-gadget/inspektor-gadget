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

package docker

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetContainerImageInfoFromImage(t *testing.T) {
	tests := []struct {
		name                string
		fullImageName       string
		expectedImageName   string
		expectedImageDigest string
	}{
		{
			name:                "canonical image name with tag and digest",
			fullImageName:       "gcr.io/k8s-minikube/kicbase:v0.0.37@sha256:8bf7a0e8a062bc5e2b71d28b35bfa9cc862d9220e234e86176b3785f685d8b15",
			expectedImageName:   "gcr.io/k8s-minikube/kicbase:v0.0.37",
			expectedImageDigest: "sha256:8bf7a0e8a062bc5e2b71d28b35bfa9cc862d9220e234e86176b3785f685d8b15",
		},
		{
			name:                "image name with tag and digest",
			fullImageName:       "busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79",
			expectedImageName:   "busybox",
			expectedImageDigest: "sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79",
		},
		{
			name:                "image name with tag",
			fullImageName:       "docker.io/library/busybox:latest",
			expectedImageName:   "docker.io/library/busybox:latest",
			expectedImageDigest: "",
		},
		{
			name:                "simple image name without tag/digest",
			fullImageName:       "busybox",
			expectedImageName:   "busybox",
			expectedImageDigest: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imageName, imageDigest := getContainerImageInfoFromImage(tt.fullImageName)
			assert.Equal(t, tt.expectedImageName, imageName)
			assert.Equal(t, tt.expectedImageDigest, imageDigest)
		})
	}
}
