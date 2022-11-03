// Copyright 2019-2022 The Inspektor Gadget authors
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

package top

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"

	"github.com/spf13/cobra"
)

type CommonTopFlags struct {
	OutputInterval int
	MaxRows        int
	SortBy         string
	ParsedSortBy   []string
}

func NewTopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Gather, sort and periodically report events according to a given criteria",
	}

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newEbpfCmd())
	cmd.AddCommand(newFileCmd())
	cmd.AddCommand(newTCPCmd())

	return cmd
}

func addCommonTopFlags(
	command *cobra.Command,
	commonTopFlags *CommonTopFlags,
	commonFlags *utils.CommonFlags,
	defaultMaxRows int,
	sortBySlice []string,
) {
	command.Flags().IntVarP(&commonTopFlags.MaxRows, "max-rows", "r", defaultMaxRows, "Maximum rows to print")
	command.Flags().StringVarP(&commonTopFlags.SortBy, "sort", "", sortBySlice[0], fmt.Sprintf("Sort by column. Join multiple columsn with ','. Prefix with '-' to sort descending for that column. Columns: (%s)", strings.Join(sortBySlice, ", ")))
	utils.AddCommonFlags(command, commonFlags)
}
