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
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/advisor"
)

var networkPolicyCmd = &cobra.Command{
	Use:   "network-policy",
	Short: "Generate network policies based on recorded network activity",
}

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
	namespaces     string
)

func init() {
	AdviseCmd.AddCommand(networkPolicyCmd)

	networkPolicyCmd.AddCommand(networkPolicyMonitorCmd)
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&namespaces, "namespaces", "", "", "Comma-separated list of namespaces to monitor")

	networkPolicyCmd.AddCommand(networkPolicyReportCmd)
	networkPolicyReportCmd.PersistentFlags().StringVarP(&inputFileName, "input", "", "", "File with recorded network activity")
	networkPolicyReportCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")
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
	return errors.New("Not implemented")
}

func runNetworkPolicyReport(cmd *cobra.Command, args []string) error {
	if inputFileName == "" {
		return utils.WrapInErrMissingArgs("--input")
	}

	adv := advisor.NewAdvisor()
	err := adv.LoadFile(inputFileName)
	if err != nil {
		return err
	}

	adv.GeneratePolicies()

	w, closure, err := newWriter(outputFileName)
	if err != nil {
		return fmt.Errorf("failed to create file %q: %w", outputFileName, err)
	}
	defer closure()

	_, err = w.Write([]byte(adv.FormatPolicies()))
	if err != nil {
		return fmt.Errorf("failed to write file %q: %w", outputFileName, err)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("failed to flush file %q: %w", outputFileName, err)
	}

	return nil
}
