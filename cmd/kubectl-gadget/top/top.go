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
	"strconv"
	"strings"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"

	"github.com/spf13/cobra"
)

type CommonTopFlags struct {
	commonFlags utils.CommonFlags

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
	sortBySlice []string,
	sortBySliceDefault []string,
) {
	command.Flags().IntVarP(&commonTopFlags.MaxRows, "max-rows", "r", top.MaxRowsDefault, "Maximum rows to print")
	command.Flags().StringVarP(&commonTopFlags.SortBy, "sort", "", strings.Join(sortBySliceDefault, ","), fmt.Sprintf("Sort by column. Join multiple columsn with ','. Prefix with '-' to sort descending for that column. Columns: (%s)", strings.Join(sortBySlice, ", ")))
	utils.AddCommonFlags(command, commonFlags)
}

// TopParser defines the interface that every top-gadget parser has to
// implement.
type TopParser[Stats any] interface {
	StartPrintLoop()
	PrintHeader()
	PrintStats()
	Callback(line string, node string)
}

// TopGadget represents a gadget belonging to the top category.
type TopGadget[Stats any] struct {
	name           string
	commonTopFlags *CommonTopFlags
	params         map[string]string
	parser         TopParser[Stats]
}

func (g *TopGadget[Stats]) Run(args []string) error {
	var err error

	if len(args) == 1 {
		g.commonTopFlags.OutputInterval, err = strconv.Atoi(args[0])
		if err != nil {
			return commonutils.WrapInErrInvalidArg("<interval>",
				fmt.Errorf("%q is not a valid value", args[0]))
		}
	} else {
		g.commonTopFlags.OutputInterval = top.IntervalDefault
	}

	sortByColumns := strings.Split(g.commonTopFlags.SortBy, ",")
	cols := columns.MustCreateColumns[Stats]()
	_, invalidCols := cols.VerifyColumnNames(sortByColumns)

	if len(invalidCols) > 0 {
		return commonutils.WrapInErrInvalidArg("--sort", fmt.Errorf("\"%v\" is/are not a recognized column(s) to sort by", strings.Join(invalidCols, ",")))
	}
	g.commonTopFlags.ParsedSortBy = sortByColumns

	if g.params == nil {
		g.params = make(map[string]string)
	}
	g.params[top.MaxRowsParam] = strconv.Itoa(g.commonTopFlags.MaxRows)
	g.params[top.IntervalParam] = strconv.Itoa(g.commonTopFlags.OutputInterval)
	g.params[top.SortByParam] = g.commonTopFlags.SortBy

	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      &g.commonTopFlags.commonFlags,
		Parameters:       g.params,
	}

	// when params.Timeout == interval it means the user
	// only wants to run for a given amount of time and print
	// that result.
	singleShot := g.commonTopFlags.commonFlags.Timeout == g.commonTopFlags.OutputInterval

	// start print loop if this is not a "single shot" operation
	if singleShot {
		g.parser.PrintHeader()
	} else {
		g.parser.StartPrintLoop()
	}

	if err := utils.RunTraceStreamCallback(config, g.parser.Callback); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	if singleShot {
		g.parser.PrintStats()
	}

	return nil
}
