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

package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"

	// This is a blank include that actually imports all gadgets - needs to be moved into another package; TODO
	_ "github.com/inspektor-gadget/inspektor-gadget/internal/operators/localmanager"

	// Another blank import for the used enricher
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection"
)

func main() {
	runtime := &local.Runtime{}

	rootCmd := &cobra.Command{
		Use:   "local-gadget",
		Short: "Collection of gadgets for containers",
	}

	// columnFilters for local-gadget
	columnFilters := []columns.ColumnFilter{columns.Or(columns.WithTag("runtime"), columns.WithNoTags())}

	var verbose bool
	rootCmd.AddCommand()
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "enables more/debug output")

	common.AddCommandsFromRegistry(rootCmd, runtime, columnFilters)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
