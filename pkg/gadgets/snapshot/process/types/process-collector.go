// Copyright 2022-2023 The Inspektor Gadget authors
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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	ShowThreadsParam = "show-threads"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID

	Command   string `json:"comm" column:"comm,template:comm"`
	Pid       int    `json:"pid" column:"pid,template:pid"`
	Tid       int    `json:"tid" column:"tid,template:pid,hide"`
	Uid       uint32 `json:"uid" column:"uid,template:uid"`
	Gid       uint32 `json:"gid" column:"gid,template:gid"`
	ParentPid int    `json:"ppid" column:"ppid,template:pid,hide"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

type processTree struct {
	process  *Event
	children []*processTree
}

func createTree(processes []*Event) (*processTree, error) {
	var root *processTree

	nodes := make(map[int]*processTree, len(processes))
	// Create a node for each process.
	for _, process := range processes {
		nodes[process.Pid] = &processTree{
			process: process,
		}
	}

	// Link all nodes together.
	// We loop on PID rather than map keys to ensure having a deterministic order.
	for _, process := range processes {
		node := nodes[process.Pid]
		ppid := node.process.ParentPid
		if _, ok := nodes[ppid]; !ok {
			if root != nil {
				return nil, fmt.Errorf("tree has two root processes: %v and %v", root, node)
			}

			root = node

			continue
		}

		nodes[ppid].children = append(nodes[ppid].children, node)
	}

	if root == nil {
		// Even if there are orphan process, they should have a parent process
		// as they will get the reaper as parent process:
		// https://elixir.bootlin.com/linux/v6.1.3/source/kernel/exit.c#L653
		// Note that above code is both called when calling exit() system call
		// and when receiving a fatal signal.
		return nil, fmt.Errorf("container has no root process")
	}

	return root, nil
}

func (t *processTree) String() string {
	var builder strings.Builder
	treeToStringBuilder(t, &builder, 0)

	return builder.String()
}

func treeToStringBuilder(node *processTree, builder *strings.Builder, depth int) {
	fmt.Fprintf(builder, "%s|-%s(%d)\n", strings.Repeat("\t", depth), node.process.Command, node.process.Pid)
	for _, child := range node.children {
		treeToStringBuilder(child, builder, depth+1)
	}
}

func WriteTree(output io.Writer, processes []*Event) error {
	containers := make(map[string][]*Event, len(processes))
	for _, process := range processes {
		containers[process.Container] = append(containers[process.Container], process)
	}

	for _, container := range containers {
		tree, err := createTree(container)
		if err != nil {
			return err
		}

		if tree.process.Namespace != "" {
			fmt.Fprintf(output, "%s/", tree.process.Namespace)
		}
		if tree.process.Pod != "" && tree.process.Pod != tree.process.Container {
			fmt.Fprintf(output, "%s/", tree.process.Pod)
		}
		fmt.Fprintln(output, tree.process.Container)

		fmt.Fprint(output, tree)
	}

	return nil
}

func PrintTree(processes []*Event) error {
	return WriteTree(os.Stdout, processes)
}
