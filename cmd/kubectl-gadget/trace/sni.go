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

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	snitypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snisnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	FmtAllSnisnoop   = "%-16.16s %-16.16s %-30.30s %s"
	FmtShortSniSnoop = "%-30.30s %s"
)

var colSnisnoopLens = map[string]int{
	"name": 30,
}

var snisnoopCmd = &cobra.Command{
	Use:   "sni",
	Short: "Trace Server Name Indication (SNI) from TLS requests",
	RunE: func(cmd *cobra.Command, args []string) error {
		transform := snisnoopTransformLine

		switch {
		case params.OutputMode == utils.OutputModeJSON: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, colSnisnoopLens)
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()
		case params.AllNamespaces:
			fmt.Printf(FmtAllSnisnoop+"\n",
				"NODE",
				"NAMESPACE",
				"POD",
				"NAME",
			)
		default:
			fmt.Printf(FmtShortSniSnoop+"\n",
				"POD",
				"NAME",
			)
		}

		config := &utils.TraceConfig{
			GadgetName:       "snisnoop",
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
	TraceCmd.AddCommand(snisnoopCmd)
	utils.AddCommonFlags(snisnoopCmd, &params)
}

func snisnoopTransformLine(line string) string {
	event := &snitypes.Event{}
	if err := json.Unmarshal([]byte(line), event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
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
		return fmt.Sprintf(FmtAllSnisnoop, event.Node, event.Namespace, event.Pod, event.Name)
	} else {
		return fmt.Sprintf(FmtShortSniSnoop, event.Pod, event.Name)
	}
}
