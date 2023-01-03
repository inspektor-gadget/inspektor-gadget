// Copyright 2022 The Inspektor Gadget authors
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
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type stsTestCase struct {
	val      uint64
	valMax   uint64
	width    uint64
	expected string
}

func TestCreateTree(t *testing.T) {
	t.Parallel()

	pid42 := Event{
		Pid: 42,
	}

	pid43 := Event{
		Pid:       43,
		ParentPid: 42,
	}

	pid44 := Event{
		Pid:       44,
		ParentPid: 42,
	}

	pid45 := Event{
		Pid:       45,
		ParentPid: 42,
	}

	pid46 := Event{
		Pid:       46,
		ParentPid: 43,
	}

	events := []*Event{
		&pid42,
		&pid43,
		&pid44,
		&pid45,
		&pid46,
	}

	tree, err := createTree(events)
	if err != nil {
		t.Fatalf("fail to create tree: %v", err)
	}

	expectedTree := &processTree{
		process: &pid42,
		children: []*processTree{
			{
				process: &pid43,
				children: []*processTree{
					{
						process: &pid46,
					},
				},
			},
			{
				process: &pid44,
			},
			{
				process: &pid45,
			},
		},
	}

	require.Equal(t, expectedTree, tree, "tree is wrong")
}

func TestCreateTreeEmpty(t *testing.T) {
	t.Parallel()

	_, err := createTree(nil)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating empty tree")
	}
}

func TestCreateTreeNoRoot(t *testing.T) {
	t.Parallel()

	// Each node is the parent of the other, so this is not a tree but a graph.
	events := []*Event{
		{
			Pid:       42,
			ParentPid: 43,
		},
		{
			Pid:       43,
			ParentPid: 42,
		},
	}

	_, err := createTree(events)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating tree without root")
	}
}

func TestCreateTreeSeveralRoots(t *testing.T) {
	t.Parallel()

	// Each node has no parent.
	events := []*Event{
		{
			Pid: 42,
		},
		{
			Pid: 43,
		},
	}

	_, err := createTree(events)
	if err == nil {
		t.Fatalf("error is nil while it was expected when creating tree with several roots")
	}
}

func TestTreeToString(t *testing.T) {
	t.Parallel()

	nodes := make([]*processTree, 5)
	i := 42
	for j := range nodes {
		nodes[j] = &processTree{
			process: &Event{
				Command: fmt.Sprintf("foo-%d", i),
				Pid:     i,
			},
			children: make([]*processTree, 0),
		}

		i++
	}

	// Node 0 is the root and has two children: 1 and 2
	nodes[0].children = append(nodes[0].children, nodes[1])
	nodes[0].children = append(nodes[0].children, nodes[2])

	// Node 2 has two children: 3 and 4 (which are leaf nodes)
	nodes[2].children = append(nodes[2].children, nodes[3])
	nodes[2].children = append(nodes[2].children, nodes[4])

	i = 0
	scanner := bufio.NewScanner(strings.NewReader(nodes[0].String()))
	for scanner.Scan() {
		line := scanner.Text()
		expected := fmt.Sprintf("%s(%d)", nodes[i].process.Command, nodes[i].process.Pid)
		if !strings.Contains(line, expected) {
			t.Fatalf("mismatched line %q does not contain %q", line, expected)
		}

		i++
	}
}
