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

package utils

import (
	"fmt"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	"github.com/spf13/cobra"
)

func AddCobraOptions[T any](cmd *cobra.Command, columns *columns.Columns[T]) {
	// Add long description to commands
	cmd.Long = cmd.Short

	cmd.Long += "\n\nAvailable columns:\n"
	for _, column := range columns.GetColumnMap() {
		cmd.Long += fmt.Sprintf("  %-20s %s\n", column.Name, column.Kind().String())
		if column.Description != "" {
			cmd.Long += fmt.Sprintf("    %s\n", column.Description)
		}
	}

	// Add features
	cmd.PersistentFlags().StringArray("filter", []string{}, "apply a filter to results; TODO: explain filter rules...")
}
