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
	"testing"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

func TestSelector(t *testing.T) {
	table := []struct {
		description string
		match       bool
		selector    *pb.ContainerSelector
		container   *pb.ContainerDefinition
	}{
		{
			description: "Selector without filter",
			match:       true,
			selector:    &pb.ContainerSelector{},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
			},
		},
		{
			description: "Selector with all filters",
			match:       true,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					{Key: "key1", Value: "value1"},
					{Key: "key2", Value: "value2"},
				},
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					{Key: "unrelated-label", Value: "here"},
					{Key: "key1", Value: "value1"},
					{Key: "key2", Value: "value2"},
				},
			},
		},
		{
			description: "Podname does not match",
			match:       false,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "a-misnamed-pod",
				Name:      "this-container",
			},
		},
		{
			description: "One label doesn't match",
			match:       false,
			selector: &pb.ContainerSelector{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					{Key: "key1", Value: "value1"},
					{Key: "key2", Value: "value2"},
				},
			},
			container: &pb.ContainerDefinition{
				Namespace: "this-namespace",
				Podname:   "this-pod",
				Name:      "this-container",
				Labels: []*pb.Label{
					{Key: "key1", Value: "value1"},
					{Key: "key2", Value: "something-else"},
				},
			},
		},
	}

	for i, entry := range table {
		result := ContainerSelectorMatches(entry.selector, entry.container)
		if entry.match != result {
			t.Fatalf("Failed test %q (index %d): result %v expected %v",
				entry.description, i, result, entry.match)
		}
	}
}
