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
	"strings"
)

// ContainerSelectorMatches tells if a container matches the criteria in a
// container selector.
func ContainerSelectorMatches(s *ContainerSelector, c *Container) bool {
	if s.K8s.Namespace != "" {
		parts := strings.Split(s.K8s.Namespace, ",")
		matched := false
		hasInclusion := false
		for _, part := range parts {
			if strings.HasPrefix(part, "!") {
				if c.K8s.Namespace == part[1:] {
					return false // Explicit exclusion
				}
			} else {
				hasInclusion = true
				if c.K8s.Namespace == part {
					matched = true
				}
			}
		}
		if hasInclusion && !matched {
			return false
		}
	}

	if s.K8s.PodName != "" {
		if strings.HasPrefix(s.K8s.PodName, "!") {
			if c.K8s.PodName == s.K8s.PodName[1:] {
				return false
			}
		} else {
			if c.K8s.PodName != s.K8s.PodName {
				return false
			}
		}
	}

	if s.K8s.ContainerName != "" {
		if strings.HasPrefix(s.K8s.ContainerName, "!") {
			if c.K8s.ContainerName == s.K8s.ContainerName[1:] {
				return false
			}
		} else {
			if c.K8s.ContainerName != s.K8s.ContainerName {
				return false
			}
		}
	}

	if s.Runtime.ContainerName != "" {
		if strings.HasPrefix(s.Runtime.ContainerName, "!") {
			if c.Runtime.ContainerName == s.Runtime.ContainerName[1:] {
				return false
			}
		} else {
			if c.Runtime.ContainerName != s.Runtime.ContainerName {
				return false
			}
		}
	}

	for sk, sv := range s.K8s.PodLabels {
		if strings.HasPrefix(sk, "!") {
			if cv, ok := c.K8s.PodLabels[sk]; ok && cv == sv[1:] {
				return false
			}
		} else {
			if cv, ok := c.K8s.PodLabels[sk]; !ok || cv != sv {
				return false
			}
		}
	}

	return true
}
