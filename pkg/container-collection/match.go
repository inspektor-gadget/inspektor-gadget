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

// matchFilterString checks if a value matches a filter string. The filter string can
// contain multiple comma-separated values. A value can be excluded by prefixing
// it with a '!'. If the filter is empty, it matches any value.
func matchFilterString(filter, value string) bool {
	if filter == "" {
		return true
	}
	parts := strings.Split(filter, ",")
	matched := false
	hasInclusion := false
	for _, part := range parts {
		if strings.HasPrefix(part, "!") {
			if value == part[1:] {
				return false // Explicit exclusion
			}
		} else {
			hasInclusion = true
			if value == part {
				matched = true
			}
		}
	}
	if hasInclusion && !matched {
		return false
	}
	return true
}

// ContainerSelectorMatches tells if a container matches the criteria in a
// container selector.
func ContainerSelectorMatches(s *ContainerSelector, c *Container) bool {
	if !matchFilterString(s.K8s.Namespace, c.K8s.Namespace) {
		return false
	}

	if !matchFilterString(s.K8s.PodName, c.K8s.PodName) {
		return false
	}

	if !matchFilterString(s.K8s.ContainerName, c.K8s.ContainerName) {
		return false
	}

	if !matchFilterString(s.Runtime.ContainerName, c.Runtime.ContainerName) {
		return false
	}

	for sk, sv := range s.K8s.PodLabels {
		if strings.HasPrefix(sk, "!") {
			if cv, ok := c.K8s.PodLabels[sk[1:]]; ok && matchFilterString(sv, cv) {
				return false
			}
		} else {
			if cv, ok := c.K8s.PodLabels[sk]; !ok || !matchFilterString(sv, cv) {
				return false
			}
		}
	}

	return true
}
