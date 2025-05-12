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

package advise

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/networkpolicy/advisor"
)

var networkPolicyMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor the network traffic",
	RunE:  runNetworkPolicyMonitor,
}

var networkPolicyReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Report network policies",
	RunE:  runNetworkPolicyReport,
}

var (
	inputFileName  string
	outputFileName string
)

func newNetworkPolicyCmd(gadgetNamespace string) *cobra.Command {
	networkPolicyCmd := &cobra.Command{
		Use:   "network-policy",
		Short: "Generate network policies based on recorded network activity",
	}
	utils.AddCommonFlags(networkPolicyCmd, &params, gadgetNamespace)

	networkPolicyCmd.AddCommand(networkPolicyMonitorCmd)
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")

	networkPolicyCmd.AddCommand(networkPolicyReportCmd)
	networkPolicyReportCmd.PersistentFlags().StringVarP(&inputFileName, "input", "", "", "File with recorded network activity")
	networkPolicyReportCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")

	return networkPolicyCmd
}

func newWriter(file string) (*bufio.Writer, func(), error) {
	var w *bufio.Writer
	var closure func()
	if outputFileName == "-" {
		w = bufio.NewWriter(os.Stdout)
		closure = func() {}
	} else {
		outputFile, err := os.Create(outputFileName)
		if err != nil {
			return nil, nil, err
		}
		closure = func() { outputFile.Close() }
		w = bufio.NewWriter(outputFile)
	}

	return w, closure, nil
}

func runNetworkPolicyMonitor(cmd *cobra.Command, args []string) error {
	w, closure, err := newWriter(outputFileName)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", outputFileName, err)
	}
	defer closure()

	config := &utils.TraceConfig{
		GadgetName:       "network-graph",
		GadgetNamespace:  gadgetNamespace,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      &params,
	}

	var mu sync.Mutex

	count := 0
	transform := func(line string) string {
		line = strings.ReplaceAll(line, "\r", "\n")
		mu.Lock()
		w.Write([]byte(line))
		w.Flush()
		mu.Unlock()
		count += 1
		if outputFileName != "-" {
			fmt.Printf("\033[2K\rRecording %d events into file %q...", count, outputFileName)
		}
		return ""
	}

	err = utils.RunTraceAndPrintStream(config, transform)
	if err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}
	return nil
}

func runNetworkPolicyReport(cmd *cobra.Command, args []string) error {
	if inputFileName == "" {
		return commonutils.WrapInErrMissingArgs("--input")
	}

	adv := advisor.NewAdvisor()
	err := adv.LoadFile(inputFileName)
	if err != nil {
		return err
	}

	adv.GeneratePolicies()

	w, closure, err := newWriter(outputFileName)
	if err != nil {
		return fmt.Errorf("creating file %q: %w", outputFileName, err)
	}
	defer closure()

	_, err = w.Write([]byte(adv.FormatPolicies()))
	if err != nil {
		return fmt.Errorf("writing file %q: %w", outputFileName, err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("flushing file %q: %w", outputFileName, err)
	}

	return nil
}
