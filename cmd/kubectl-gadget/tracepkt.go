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
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	tracepkttypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/tracepkt/types"
)

const (
	TRACEPKT_FMT_ALL   = "%-16.16s %-24.24s %-20.20s %-12.12s %-16.16s %-8.8s %-8.8s %s"
	TRACEPKT_FMT_SHORT = "%-12.12s %-16.16s %-8.8s %s"
)

var tracepktColLens = map[string]int{
	"table_name": 12,
	"chain_name": 16,
	"comment":    8,
}

var tracepktCmd = &cobra.Command{
	Use:   "tracepkt",
	Short: "Trace DNS requests",
	Run: func(cmd *cobra.Command, args []string) {
		transform := tracepktTransformLine()

		switch {
		case params.OutputMode == utils.OutputModeJson: // don't print any header
		case params.OutputMode == utils.OutputModeCustomColumns:
			table := utils.NewTableFormater(params.CustomColumns, tracepktColLens)
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()
		case params.Verbose:
			fmt.Printf(TRACEPKT_FMT_ALL+"\n",
				"NODE",
				"NETNS",
				"IFACES",
				"TABLE",
				"CHAIN",
				"COMMENT",
				"RULENUM",
				"RULE",
			)
		default:
			fmt.Printf(TRACEPKT_FMT_SHORT+"\n",
				"TABLE",
				"CHAIN",
				"COMMENT",
				"RULE",
			)
		}

		config := &utils.TraceConfig{
			GadgetName:       "tracepkt",
			Operation:        "start",
			TraceOutputMode:  "Stream",
			TraceOutputState: "Started",
			CommonFlags:      &params,
		}

		err := utils.RunTraceAndPrintStream(config, transform)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)

			os.Exit(1)
		}
	},
}

var tracepktAddTraceCmd = &cobra.Command{
	Use:          "add-trace <trace-id>",
	Short:        "Add a trace on the specified pod",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("it is necessary to specify a <trace-id>")
		}
		traceID := args[0]

		err := utils.SetTraceOperation(traceID, "add-trace")
		if err != nil {
			return err
		}

		fmt.Printf("AddTrace TODO\n")
		return nil
	},
}

var tracepktRemoveTraceCmd = &cobra.Command{
	Use:          "remove-trace <trace-id>",
	Short:        "Remove a trace on the specified pod",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("it is necessary to specify a <trace-id>")
		}
		traceID := args[0]

		err := utils.SetTraceOperation(traceID, "remove-trace")
		if err != nil {
			return err
		}

		fmt.Printf("AddTrace TODO\n")
		return nil
	},
}

func init() {
	tracepktCmd.AddCommand(tracepktAddTraceCmd)
	tracepktCmd.AddCommand(tracepktRemoveTraceCmd)

	utils.AddCommonFlags(tracepktAddTraceCmd, &params)
	utils.AddCommonFlags(tracepktRemoveTraceCmd, &params)

	rootCmd.AddCommand(tracepktCmd)
	utils.AddCommonFlags(tracepktCmd, &params)
}

func tracepktTransformLine() func(line string) string {
	indent := 0
	stack := []int{0}
	previousEvent := tracepkttypes.Event{}

	return func(line string) string {
		color.NoColor = false
		event := &tracepkttypes.Event{}
		json.Unmarshal([]byte(line), event)

		podMsgSuffix := ""
		if event.Namespace != "" && event.Pod != "" {
			podMsgSuffix = ", pod " + event.Namespace + "/" + event.Pod
		}

		if event.Err != "" {
			return fmt.Sprintf("Error on node %s%s: %s: %s", event.Node, podMsgSuffix, event.Notice, event.Err)
		}
		if event.Notice != "" {
			if !params.Verbose {
				return ""
			}
			return fmt.Sprintf("Notice on node %s%s: %s", event.Node, podMsgSuffix, event.Notice)
		}

		switch event.Comment {
		case "rule":
			event.Rule = strings.TrimPrefix(event.Rule, fmt.Sprintf("-A %s ", event.ChainName))
		case "return":
			event.Rule = strings.TrimPrefix(event.Rule, fmt.Sprintf("-N %s", event.ChainName))
		case "policy":
			event.Rule = strings.TrimPrefix(event.Rule, fmt.Sprintf("-P %s ", event.ChainName))
		}

		if params.Verbose {
			return fmt.Sprintf(TRACEPKT_FMT_ALL,
				event.Node,
				fmt.Sprintf("%d->%d", event.NetnsIn, event.NetnsOut),
				fmt.Sprintf("%s->%s", event.InterfaceNameIn, event.InterfaceNameOut),
				event.TableName,
				event.ChainName,
				event.Comment,
				fmt.Sprint(event.RuleNum),
				event.Rule,
			)
		} else {
			out := ""
			if previousEvent.TableName != event.TableName {
				indent = 0
				stack = []int{0}
			} else if previousEvent.ChainName != event.ChainName && previousEvent.Comment == "rule" {
				if strings.Contains(previousEvent.Rule, "-j "+event.ChainName) {
					indent++
					stack = append(stack, 0)
				} else if strings.Contains(previousEvent.Rule, "-g "+event.ChainName) {
					indent = 0
					stack = []int{0}
				}
			}
			italic := color.New(color.Italic).SprintfFunc()
			for i := stack[len(stack)-1] + 1; i < event.RuleNum; i++ {
				rules := strings.Split(event.Rules, "\n")
				if i < len(rules) {
					r := strings.TrimPrefix(rules[i], fmt.Sprintf("-A %s ", event.ChainName))
					out += strings.Repeat("    ", indent)
					out += italic("%s/%s [%s] #%d %s\n", event.TableName, event.ChainName, "skip", i, r)
				}
			}
			stack[len(stack)-1] = event.RuleNum
			bold := color.New(color.Bold).SprintFunc()
			out += strings.Repeat("    ", indent)
			out += fmt.Sprintf("%s/%s [%s] #%d %s", event.TableName, event.ChainName, bold(event.Comment), event.RuleNum, event.Rule)

			if event.Comment == "policy" || event.Comment == "return" || strings.Contains(event.Rule, "-j RETURN") {
				if indent > 0 {
					indent--
				}
				if len(stack) > 1 {
					stack = stack[:len(stack)-1]
				}
			}

			if event.Comment == "rule" || event.Comment == "policy" {
				red := color.New(color.Bold, color.FgRed).SprintFunc()
				green := color.New(color.Bold, color.FgGreen).SprintFunc()
				out = strings.Replace(out, "DROP", red("DROP"), -1)
				out = strings.Replace(out, "ACCEPT", green("ACCEPT"), -1)
			}

			previousEvent = *event
			return out
			// return fmt.Sprintf(TRACEPKT_FMT_SHORT, event.TableName, event.ChainName, event.Comment, event.Rule)
		}
	}
}
