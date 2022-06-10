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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Trace DNS requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		// print header
		switch params.OutputMode {
		case utils.OutputModeCustomColumns:
			fmt.Println(getCustomDNSColsHeader(params.CustomColumns))
		case utils.OutputModeColumns:
			fmt.Printf("%-16s %-16s %-16s %-9s %-10s %s\n",
				"NODE", "NAMESPACE", "POD",
				"TYPE", "QTYPE", "NAME")
		}

		config := &utils.TraceConfig{
			GadgetName:       "dns",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, dnsTransformLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(dnsCmd)
	utils.AddCommonFlags(dnsCmd, &params)
}

// dnsTransformLine is called to transform an event to columns
// format according to the parameters
func dnsTransformLine(line string) string {
	var sb strings.Builder
	var e types.Event

	if err := json.Unmarshal([]byte(line), &e); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if e.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(e.Event, params.Verbose)
		return ""
	}

	switch params.OutputMode {
	case utils.OutputModeColumns:
		sb.WriteString(fmt.Sprintf("%-16s %-16s %-16s %-9s %-10s %s",
			e.Node, e.Namespace, e.Pod, e.PktType, e.QType, e.DNSName))
	case utils.OutputModeCustomColumns:
		for _, col := range params.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%-16s", e.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%-16s", e.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%-16s", e.Pod))
			case "type":
				sb.WriteString(fmt.Sprintf("%-9s", e.PktType))
			case "qtype":
				sb.WriteString(fmt.Sprintf("%-10s", e.QType))
			case "name":
				sb.WriteString(fmt.Sprintf("%-24s", e.DNSName))
			}
			sb.WriteRune(' ')
		}
	}

	return sb.String()
}

func getCustomDNSColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "type":
			sb.WriteString(fmt.Sprintf("%-9s", "TYPE"))
		case "qtype":
			sb.WriteString(fmt.Sprintf("%-10s", "QTYPE"))
		case "name":
			sb.WriteString(fmt.Sprintf("%-24s", "NAME"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
