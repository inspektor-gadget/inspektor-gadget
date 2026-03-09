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
func matchFilterString(filter string, values ...string) bool {
	if filter == "" {
		return true
	}
	return matchFilterParts(strings.Split(filter, ","), values...)
}

func matchFilterParts(parts []string, values ...string) bool {
	matched := false
	hasInclusion := false
	for _, part := range parts {
		if strings.HasPrefix(part, "!") {
			excl := part[1:]
			for _, v := range values {
				if v == excl {
					return false // Explicit exclusion
				}
			}
		} else {
			hasInclusion = true
			for _, v := range values {
				if v == part {
					matched = true
				}
			}
		}
	}
	if hasInclusion && !matched {
		return false
	}
	return true
}

func matchFilterWithCleaner(filter string, cleaner func(string) string, values ...string) bool {
	if filter == "" {
		return true
	}

	parts := strings.Split(filter, ",")
	for i, p := range parts {
		if strings.HasPrefix(p, "!") {
			parts[i] = "!" + cleaner(p[1:])
		} else {
			parts[i] = cleaner(p)
		}
	}

	cleanedValues := make([]string, len(values))
	for i, v := range values {
		cleanedValues[i] = cleaner(v)
	}

	return matchFilterParts(parts, cleanedValues...)
}

// cleanDigest trims a digest to its first 12 characters, stripping
// any algorithm prefix if present.
func cleanDigest(d string) string {
	// Strip algo prefix if present (e.g. sha256:...)
	if idx := strings.Index(d, ":"); idx != -1 {
		d = d[idx+1:]
	}
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// cleanImageID is a convenience function to clean image IDs (the same way as digests)
func cleanImageID(id string) string {
	return cleanDigest(id)
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

	if !matchFilterWithCleaner(s.Runtime.ContainerImageID, cleanImageID, c.Runtime.ContainerImageID) {
		return false
	}

	if !matchFilterWithCleaner(s.Runtime.ContainerImageDigest, cleanDigest, c.Runtime.ContainerImageDigest) {
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
