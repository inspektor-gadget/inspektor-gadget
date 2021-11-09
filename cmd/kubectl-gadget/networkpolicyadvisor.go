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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/advisor"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy/types"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var networkPolicyCmd = &cobra.Command{
	Use:   "network-policy",
	Short: "Generate network policies based on recorded network activity",
}

var networkPolicyMonitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Monitor the network traffic",
	Run:   runNetworkPolicyMonitor,
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
	rootCmd.AddCommand(networkPolicyCmd)

	networkPolicyCmd.AddCommand(networkPolicyMonitorCmd)
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&namespaces, "namespaces", "", "", "Comma-separated list of namespaces to monitor")

	networkPolicyCmd.AddCommand(networkPolicyReportCmd)
	networkPolicyReportCmd.PersistentFlags().StringVarP(&inputFileName, "input", "", "", "File with recorded network activity")
	networkPolicyReportCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")
}

type traceCollector struct {
	m      *sync.Mutex
	writer *bufio.Writer
	node   string
}

func (t traceCollector) Write(p []byte) (n int, err error) {
	t.m.Lock()
	defer t.m.Unlock()

	event := types.KubernetesConnectionEvent{}
	text := strings.TrimSpace(string(p))
	if len(text) != 0 {
		err := json.Unmarshal([]byte(text), &event)
		if err == nil && event.Type == "ready" {
			fmt.Printf("Node %s ready.\n", t.node)
		}
	}

	n, err = t.writer.Write(p)
	if err != nil {
		return
	}
	err = t.writer.Flush()
	return
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

func runNetworkPolicyMonitor(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget network-policy monitor",
		"args":    args,
	})

	w, closure, err := newWriter(outputFileName)
	if err != nil {
		contextLogger.Fatalf("Error creating file %q: %s", outputFileName, err)
	}
	defer closure()

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error setting up Kubernetes client: %s", err)
	}

	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metaV1.ListOptions{})
	if err != nil {
		contextLogger.Fatalf("Error listing nodes: %s", err)
	}

	if namespaces == "" {
		namespaces = utils.GetNamespace()
	}
	namespaceFilter := fmt.Sprintf("--namespace %q", namespaces)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	failure := make(chan string)

	var m sync.Mutex
	for _, node := range nodes.Items {
		go func(nodeName string) {
			collector := traceCollector{&m, w, nodeName}
			cmd := fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --nomanager --probecleanup --gadget /bin/networkpolicyadvisor -- %s",
				namespaceFilter)
			err := utils.ExecPod(client, nodeName, cmd, collector, os.Stderr)
			if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
				failure <- fmt.Sprintf("Error running command: %s\n", err)
			}
		}(node.Name)
	}

	select {
	case <-sigs:
		fmt.Printf("\nStopping...\n")
	case e := <-failure:
		fmt.Printf("Error detected: %s\n", e)
	}

	for _, node := range nodes.Items {
		_, _, err := utils.ExecPodCapture(client, node.Name,
			fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --stop"))
		if err != nil {
			fmt.Printf("Error running command: %s\n", err)
		}
	}
}

func runNetworkPolicyReport(cmd *cobra.Command, args []string) error {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget network-policy report",
		"args":    args,
	})
	if inputFileName == "" {
		return fmt.Errorf("Parameter --input missing")
	}

	adv := advisor.NewAdvisor()
	err := adv.LoadFile(inputFileName)
	if err != nil {
		return err
	}

	adv.GeneratePolicies()

	w, closure, err := newWriter(outputFileName)
	if err != nil {
		contextLogger.Fatalf("Error creating file %q: %s", outputFileName, err)
	}
	defer closure()

	_, err = w.Write([]byte(adv.FormatPolicies()))
	if err != nil {
		contextLogger.Fatalf("Error writing file %q: %s", outputFileName, err)
	}
	err = w.Flush()
	if err != nil {
		contextLogger.Fatalf("Error writing file %q: %s", outputFileName, err)
	}

	return nil
}
