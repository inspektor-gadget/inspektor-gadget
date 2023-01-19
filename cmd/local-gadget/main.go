// Copyright 2019-2023 The Inspektor Gadget authors
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
	"os"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// This is a blank include that actually imports all gadgets - needs to be moved into another package; TODO
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection"

	// Another blank import for the used operator
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "local-gadget",
		Short: "Collection of gadgets for containers",
	}

	rootCmd.AddCommand(
		containers.NewListContainersCmd(),
		newVersionCmd(),
	)

	runtime := &local.Runtime{}
	// columnFilters for local-gadget
	columnFilters := []columns.ColumnFilter{columns.Or(columns.WithTag("runtime"), columns.WithNoTags())}
	common.AddCommandsFromRegistry(rootCmd, runtime, columnFilters)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
