// Copyright 2023 The Inspektor Gadget authors
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

import "github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

type Event struct {
	// Node where the event comes from
	Node   string `json:"node,omitempty" column:"node,template:node" columnTags:"kubernetes"`
	Output string `json:"output" column:"output,width:120"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func (ev *Event) SetNode(node string) {
	ev.Node = node
}
