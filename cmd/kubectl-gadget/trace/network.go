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
	networktypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/network-graph/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	FmtShortNetwork = "%-30.30s %-9.9s %-5.5s %-4.4s %s"
	FmtAllNetwork   = "%-16.16s %-16.16s " + FmtShortNetwork
)

var colNetworkLens = map[string]int{
	"event": 30,
}

var networkCmd = &cobra.Command{
	Use:   "network",
	Short: "Trace network streams",
	RunE: func(cmd *cobra.Command, args []string) error {
		switch {
		case params.OutputMode == utils.OutputModeJSON: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
		case params.AllNamespaces:
			fmt.Printf(FmtAllNetwork+"\n",
				"NODE",
				"NAMESPACE",
				"POD",
				"TYPE",
				"PROTO",
				"PORT",
				"REMOTE",
			)
		default:
			fmt.Printf(FmtShortNetwork+"\n",
				"POD",
				"TYPE",
				"PROTO",
				"PORT",
				"REMOTE",
			)
		}

		config := &utils.TraceConfig{
			GadgetName:       "network-graph",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transformNetworkLine)
		if err != nil {
			return utils.WrapInErrRunGadget(err)
		}

		return nil
	},
}

func init() {
	TraceCmd.AddCommand(networkCmd)
	utils.AddCommonFlags(networkCmd, &params)
}

func transformNetworkLine(line string) string {
	event := &networktypes.Event{}
	if err := json.Unmarshal([]byte(line), event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
		return ""
	}

	if event.Type != eventtypes.NORMAL {
		utils.ManageSpecialEvent(event.Event, params.Verbose)
		return ""
	}

	if event.Pod == "" {
		// ignore events on host netns for now
		return ""
	}

	remote := ""
	switch event.RemoteKind {
	case "pod":
		remote = fmt.Sprintf("pod %s/%s", event.RemotePodNamespace, event.RemotePodName)
	case "svc":
		remote = fmt.Sprintf("svc %s/%s", event.RemoteSvcNamespace, event.RemoteSvcName)
	case "other":
		remote = fmt.Sprintf("endpoint %s", event.RemoteOther)
	default:
		remote = fmt.Sprintf("? %s", event.Debug)
	}

	if params.AllNamespaces {
		return fmt.Sprintf(FmtAllNetwork,
			event.Node, event.Namespace, event.Pod,
			event.PktType, event.Proto, fmt.Sprint(event.Port),
			remote)
	} else {
		return fmt.Sprintf(FmtShortNetwork, event.Pod,
			event.PktType, event.Proto, fmt.Sprint(event.Port),
			remote)
	}
}
