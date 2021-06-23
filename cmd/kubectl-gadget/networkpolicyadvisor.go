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
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy"
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
	networkPolicyCmd.PersistentFlags().String(
		"input",
		"",
		"recorded network activity file")
	viper.BindPFlag("input", networkPolicyCmd.PersistentFlags().Lookup("input"))

	rootCmd.AddCommand(networkPolicyCmd)

	networkPolicyCmd.AddCommand(networkPolicyMonitorCmd)
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&outputFileName, "output", "", "-", "File name output")
	networkPolicyMonitorCmd.PersistentFlags().StringVarP(&namespaces, "namespaces", "", "default", "Comma-separated list of namespaces to monitor")

	networkPolicyCmd.AddCommand(networkPolicyReportCmd)
	networkPolicyReportCmd.PersistentFlags().StringVarP(&inputFileName, "input", "", "-", "File name input")
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

func runNetworkPolicyMonitor(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget network-policy monitor",
		"args":    args,
	})

	var w *bufio.Writer
	if outputFileName == "-" {
		w = bufio.NewWriter(os.Stdout)
	} else {
		outputFile, err := os.Create(outputFileName)
		if err != nil {
			contextLogger.Fatalf("Error creating file %q: %q", outputFileName, err)
		}
		defer outputFile.Close()
		w = bufio.NewWriter(outputFile)
	}

	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error setting up Kubernetes client: %q", err)
	}

	var listOptions = metaV1.ListOptions{
		LabelSelector: labels.Everything().String(),
		FieldSelector: fields.Everything().String(),
	}
	nodes, err := client.CoreV1().Nodes().List(context.TODO(), listOptions)
	if err != nil {
		contextLogger.Fatalf("Error listing nodes: %q", err)
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
			err := execPod(client, nodeName, cmd, collector, os.Stderr)
			if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
				failure <- fmt.Sprintf("Error running command: %q\n", err)
			}
		}(node.Name)
	}

	select {
	case <-sigs:
		fmt.Printf("\nStopping...\n")
	case e := <-failure:
		fmt.Printf("Error detected: %q\n", e)
	}

	for _, node := range nodes.Items {
		_, _, err := execPodCapture(client, node.Name,
			fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid networkpolicyadvisor --stop"))
		if err != nil {
			fmt.Printf("Error running command: %q\n", err)
		}
	}
}

func runNetworkPolicyReport(cmd *cobra.Command, args []string) error {
	if inputFileName == "" {
		return fmt.Errorf("Parameter --input missing")
	}

	advisor := networkpolicy.NewAdvisor()
	err := advisor.LoadFile(inputFileName)
	if err != nil {
		return err
	}

	advisor.GeneratePolicies()
	fmt.Printf(advisor.FormatPolicies())

	return err
}
