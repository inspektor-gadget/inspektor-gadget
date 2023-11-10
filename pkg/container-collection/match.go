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
	"slices"
	"strings"
)

// ContainerSelectorMatches tells if a container matches the criteria in a
// container selector.
func ContainerSelectorMatches(s *ContainerSelector, c *Container) bool {
	if s.K8s.Namespace != "" && !slices.Contains(strings.Split(s.K8s.Namespace, ","), c.K8s.Namespace) {
		return false
	}
	if s.K8s.PodName != "" && s.K8s.PodName != c.K8s.PodName {
		return false
	}
	if s.K8s.ContainerName != "" && s.K8s.ContainerName != c.K8s.ContainerName {
		return false
	}
	if s.Runtime.ContainerName != "" && s.Runtime.ContainerName != c.Runtime.ContainerName {
		return false
	}
	for sk, sv := range s.K8s.PodLabels {
		if cv, ok := c.K8s.PodLabels[sk]; !ok || cv != sv {
			return false
		}
	}
	return true
}
