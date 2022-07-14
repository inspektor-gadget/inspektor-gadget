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

	"golang.org/x/exp/slices"
)

// ContainerSelectorMatches tells if a container matches the criteria in a
// container selector.
func ContainerSelectorMatches(s *ContainerSelector, c *Container) bool {
	if s.Namespace != "" && !slices.Contains(strings.Split(s.Namespace, ","), c.Namespace) {
		return false
	}
	if s.Podname != "" && s.Podname != c.Podname {
		return false
	}
	if s.Name != "" && s.Name != c.Name {
		return false
	}
	for sk, sv := range s.Labels {
		if cv, ok := c.Labels[sk]; !ok || cv != sv {
			return false
		}
	}

	return true
}
