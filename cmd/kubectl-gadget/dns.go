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

package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	dnstypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns/types"
)

var (
	dnsParams utils.CommonFlags
)

const (
	FMT_ALL   = "%-16.16s %-16.16s %-30.30s %-9.9s %s"
	FMT_SHORT = "%-30.30s %-9.9s %s"
)

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Trace DNS requests",
	Run: func(cmd *cobra.Command, args []string) {
		if !dnsParams.JsonOutput {
			if dnsParams.AllNamespaces {
				fmt.Printf(FMT_ALL+"\n",
					"NODE",
					"NAMESPACE",
					"POD",
					"TYPE",
					"NAME",
				)
			} else {
				fmt.Printf(FMT_SHORT+"\n",
					"POD",
					"TYPE",
					"NAME",
				)
			}
		}

		utils.GenericTraceCommand("dns", &dnsParams, args, "Stream", nil, transformLine)
	},
}

func init() {
	rootCmd.AddCommand(dnsCmd)
	utils.AddCommonFlags(dnsCmd, &dnsParams)
}

func transformLine(line string) string {
	event := &dnstypes.Event{}
	json.Unmarshal([]byte(line), event)
	if event.Err != "" {
		return fmt.Sprintf("Error on node %s: %s: %s", event.Node, event.Notice, event.Err)
	}
	if event.Notice != "" {
		return fmt.Sprintf("Notice on node %s %s/%s: %s", event.Node, event.Namespace, event.Pod, event.Notice)
	}
	if dnsParams.AllNamespaces {
		return fmt.Sprintf(FMT_ALL, event.Node, event.Namespace, event.Pod, event.PktType, event.DNSName)
	} else {
		return fmt.Sprintf(FMT_SHORT, event.Pod, event.PktType, event.DNSName)
	}
}
