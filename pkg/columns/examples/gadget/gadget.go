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

package main

import (
	"fmt"
	"os"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/kinvolk/inspektor-gadget/pkg/columns/formatter/textcolumns"
)

type Kubernetes struct {
	Node      string `column:"node" columnTags:"kubernetes"`
	Container string `column:"container" columnTags:"kubernetes"`
	Pod       string `column:"pod" columnTags:"kubernetes"`
}

type Runtime struct {
	Runtime string `column:"runtime" columnTags:"runtime"`
}

type GadgetData struct {
	Kubernetes
	Runtime
	GadgetData string `column:"gadgetData"`
}

var GadgetOutput = []*GadgetData{
	{
		Kubernetes: Kubernetes{
			Node:      "Node 1",
			Container: "Container 1",
			Pod:       "Pod 1",
		},
		Runtime:    Runtime{Runtime: "Runtime 1"},
		GadgetData: "Data 1",
	},
	{
		Kubernetes: Kubernetes{
			Node:      "Node 2",
			Container: "Container 2",
			Pod:       "Pod 2",
		},
		Runtime:    Runtime{Runtime: "Runtime 2"},
		GadgetData: "Data 2",
	},
	{
		Kubernetes: Kubernetes{
			Node:      "Node 3",
			Container: "Container 3",
			Pod:       "Pod 3",
		},
		Runtime:    Runtime{Runtime: "Runtime 3"},
		GadgetData: "Data 3",
	},
}

// Defining the column helper here lets the program crash on start if there are
// errors in the syntax
var gadgetColumns = columns.MustCreateColumns[GadgetData]()

func main() {
	// Get columnMap
	cmap := gadgetColumns.GetColumnMap()

	// Get a new formatter and output all data
	formatter := textcolumns.NewFormatter(cmap, textcolumns.WithAutoScale(false))
	formatter.WriteTable(os.Stdout, GadgetOutput)

	/*
		NODE             CONTAINER        POD              RUNTIME          GADGETDATA
		————————————————————————————————————————————————————————————————————————————————————
		Node 1           Container 1      Pod 1            Runtime 1        Data 1
		Node 2           Container 2      Pod 2            Runtime 2        Data 2
		Node 3           Container 3      Pod 3            Runtime 3        Data 3
	*/

	fmt.Println()

	// Leave out kubernetes info for this one, but include gadget data (not-embedded struct) and runtime information
	formatter = textcolumns.NewFormatter(
		gadgetColumns.GetColumnMap(columns.Or(columns.WithEmbedded(false), columns.WithTag("runtime"))),
		textcolumns.WithAutoScale(false),
	)
	formatter.WriteTable(os.Stdout, GadgetOutput)

	/*
		RUNTIME          GADGETDATA
		—————————————————————————————————
		Runtime 1        Data 1
		Runtime 2        Data 2
		Runtime 3        Data 3
	*/
}
