// Copyright 2019-2021 The Inspektor Gadget authors
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

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	dnstypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	FmtShortDNS = "%-30.30s %-9.9s %-10.10s %s"
	FmtAllDNS   = "%-16.16s %-16.16s " + FmtShortDNS
)

var colLens = map[string]int{
	"pkt_type": 10,
	"name":     30,
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Trace DNS requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		transform := transformLine

		switch {
		case params.OutputMode == utils.OutputModeJSON: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, colLens)
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()
		case params.AllNamespaces:
			fmt.Printf(FmtAllDNS+"\n",
				"NODE",
				"NAMESPACE",
				"POD",
				"TYPE",
				"QTYPE",
				"NAME",
			)
		default:
			fmt.Printf(FmtShortDNS+"\n",
				"POD",
				"TYPE",
				"QTYPE",
				"NAME",
			)
		}

		config := &utils.TraceConfig{
			GadgetName:       "dns",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transform)
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

func transformLine(line string) string {
	event := &dnstypes.Event{}
	if err := json.Unmarshal([]byte(line), event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	podMsgSuffix := ""
	if event.Namespace != "" && event.Pod != "" {
		podMsgSuffix = ", pod " + event.Namespace + "/" + event.Pod
	}

	if event.Type == eventtypes.ERR {
		return fmt.Sprintf("Error on node %s%s: %s", event.Node, podMsgSuffix, event.Message)
	}
	if event.Type == eventtypes.DEBUG {
		if !params.Verbose {
			return ""
		}
		return fmt.Sprintf("Debug on node %s%s: %s", event.Node, podMsgSuffix, event.Message)
	}
	if params.AllNamespaces {
		return fmt.Sprintf(FmtAllDNS, event.Node, event.Namespace, event.Pod, event.PktType, event.QType, event.DNSName)
	} else {
		return fmt.Sprintf(FmtShortDNS, event.Pod, event.PktType, event.QType, event.DNSName)
	}
}
