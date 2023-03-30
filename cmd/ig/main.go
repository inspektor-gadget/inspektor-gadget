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
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/ig/containers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"

	// This is a blank include that actually imports all gadgets - needs to be moved into another package; TODO
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection"

	// Another blank import for the used operator
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "ig",
		Short: "Collection of gadgets for containers",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if os.Geteuid() != 0 {
				return fmt.Errorf("%s must be run as root to be able to run eBPF programs", os.Args[0])
			}

			return nil
		},
	}

	rootCmd.AddCommand(
		containers.NewListContainersCmd(),
		newVersionCmd(),
	)

	runtime := local.New()
	// columnFilters for ig
	columnFilters := []columns.ColumnFilter{columns.Or(columns.WithTag("runtime"), columns.WithNoTags())}
	common.AddCommandsFromRegistry(rootCmd, runtime, columnFilters)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	environment.Environment = environment.Local
}
