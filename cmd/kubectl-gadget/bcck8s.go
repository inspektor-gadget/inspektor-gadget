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
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var biotopCmd = &cobra.Command{
	Use:   "biotop",
	Short: "Trace block device I/O",
	Run:   bccCmd("biotop"),
}

var execsnoopCmd = &cobra.Command{
	Use:   "execsnoop",
	Short: "Trace new processes",
	Run:   bccCmd("execsnoop"),
}

var mountsnoopCmd = &cobra.Command{
	Use:   "mountsnoop",
	Short: "Trace mount and umount syscalls",
	Run:   bccCmd("mountsnoop"),
}

var opensnoopCmd = &cobra.Command{
	Use:   "opensnoop",
	Short: "Trace open() system calls",
	Run:   bccCmd("opensnoop"),
}

var bindsnoopCmd = &cobra.Command{
	Use:   "bindsnoop",
	Short: "Trace IPv4 and IPv6 bind() system calls",
	Run:   bccCmd("bindsnoop"),
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Profile CPU usage by sampling stack traces",
	Run:   bccCmd("profile"),
}

var tcptopCmd = &cobra.Command{
	Use:   "tcptop",
	Short: "Show the TCP traffic in a pod",
	Run:   bccCmd("tcptop"),
}

var tcpconnectCmd = &cobra.Command{
	Use:   "tcpconnect",
	Short: "Trace TCP connect() system calls",
	Run:   bccCmd("tcpconnect"),
}

var tcptracerCmd = &cobra.Command{
	Use:   "tcptracer",
	Short: "Trace tcp connect, accept and close",
	Run:   bccCmd("tcptracer"),
}

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Suggest Security Capabilities for securityContext",
	Run:   bccCmd("capabilities"),
}

var (
	toolMode string

	stackFlag  bool
	uniqueFlag bool

	profileKernel bool
	profileUser   bool
)

const (
	// Use the value passed at deployment time with --default-tool-mode
	ToolModeDefault = "default"
	// Probe the best mode supported for the tool
	ToolModeAuto = "auto"
	// Use eBPF CORE tools
	ToolModeCore = "core"
	// Use Python base tools
	ToolModeStandard = "standard"
)

var supportedToolModes = []string{ToolModeDefault, ToolModeAuto, ToolModeCore, ToolModeStandard}

func init() {
	commands := []*cobra.Command{
		biotopCmd,
		execsnoopCmd,
		mountsnoopCmd,
		opensnoopCmd,
		bindsnoopCmd,
		profileCmd,
		tcptopCmd,
		tcpconnectCmd,
		tcptracerCmd,
		capabilitiesCmd,
	}

	// Add flags for all BCC gadgets
	for _, command := range commands {
		rootCmd.AddCommand(command)
		utils.AddCommonFlags(command, &params)

		command.PersistentFlags().StringVarP(
			&toolMode,
			"tool-mode",
			"",
			ToolModeDefault,
			fmt.Sprintf("Tools mode (%s).", strings.Join(supportedToolModes, ", ")),
		)

	}

	// Add flags specific to some BCC gadgets
	capabilitiesCmd.PersistentFlags().BoolVarP(
		&stackFlag,
		"print-stack",
		"",
		false,
		"Print kernel and userspace call stack of cap_capable()",
	)
	capabilitiesCmd.PersistentFlags().BoolVarP(
		&uniqueFlag,
		"unique",
		"",
		false,
		"Don't print duplicate capability checks",
	)

	profileCmd.PersistentFlags().BoolVarP(
		&profileUser,
		"user",
		"U",
		false,
		"Show stacks from user space only (no kernel space stacks)",
	)
	profileCmd.PersistentFlags().BoolVarP(
		&profileKernel,
		"kernel",
		"K",
		false,
		"Show stacks from kernel space only (no user space stacks)",
	)
}

func bccCmd(subCommand string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"command": fmt.Sprintf("kubectl-gadget %s", subCommand),
			"args":    args,
		})

		client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		// tcptop only works on one pod at a time
		if subCommand == "tcptop" {
			if params.Node == "" || params.Podname == "" {
				contextLogger.Fatalf("tcptop only works with --node and --podname")
			}

			if params.OutputMode == utils.OutputModeJson {
				contextLogger.Fatalf("tcptop doesn't support --json")
			}
		}

		// biotop only works per node
		if subCommand == "biotop" {
			if params.Node == "" {
				contextLogger.Fatalf("biotop only works with --node")
			}

			if params.Containername != "" || params.Podname != "" {
				contextLogger.Fatalf("biotop doesn't support --containername or --podname")
			}

			if params.AllNamespaces {
				contextLogger.Fatalf("biotop only works with --all-namespaces")
			}

			if params.OutputMode == utils.OutputModeJson {
				contextLogger.Fatalf("biotop doesn't support --json")
			}
		}

		// Tools Mode
		toolModeValid := false
		for _, val := range supportedToolModes {
			if toolMode == val {
				toolModeValid = true
				break
			}
		}

		if !toolModeValid {
			contextLogger.Fatalf("%q is not a valid value for --tool-mode", toolMode)
		}

		// check if the gadget supports core mode
		if subCommand == "biotopCmd" || subCommand == "profile" || subCommand == "tcptop" ||
			subCommand == "capabilities" {
			if toolMode == ToolModeCore {
				contextLogger.Fatalf("gadget %s doesn't support core mode", subCommand)
			}

			// force these gadgets to use the standard version
			if toolMode == ToolModeAuto {
				toolMode = ToolModeStandard
			}
		}

		labelFilter := ""
		if params.LabelsRaw != "" {
			labelFilter = fmt.Sprintf("--label %s", params.LabelsRaw)
		}

		namespaceFilter := ""
		if !params.AllNamespaces {
			namespaceFilter = fmt.Sprintf("--namespace %s", params.Namespace)
		}

		podnameFilter := ""
		if params.Podname != "" {
			podnameFilter = fmt.Sprintf("--podname %s", params.Podname)
		}

		containernameFilter := ""
		if params.Containername != "" {
			containernameFilter = fmt.Sprintf("--containername %s", params.Containername)
		}

		extraParams := ""

		// disable manager for biotop
		if subCommand == "biotop" {
			extraParams += " --nomanager"
		}

		gadgetParams := ""

		// add container info to gadgets that support it
		if subCommand != "tcptop" && subCommand != "profile" {
			gadgetParams = "--containersmap /sys/fs/bpf/gadget/containers"
		}

		var transform func(line string) string

		if params.OutputMode == utils.OutputModeCustomColumns {
			table := utils.NewTableFormater(params.CustomColumns, map[string]int{})
			fmt.Println(table.GetHeader())
			transform = table.GetTransformFunc()

			// ask the gadget to send the output in json mode to be able to
			// parse it to print only the columns required by the user
			params.OutputMode = utils.OutputModeJson
		}

		if params.OutputMode == utils.OutputModeJson {
			gadgetParams += " --json"
		}

		switch subCommand {
		case "capabilities":
			if stackFlag {
				gadgetParams += " -K"
			}
			if uniqueFlag {
				gadgetParams += " --unique"
			}
			if params.Verbose {
				gadgetParams += " -v"
			}
		case "profile":
			gadgetParams += " -f -d "
			if profileUser {
				gadgetParams += " -U "
			} else if profileKernel {
				gadgetParams += " -K "
			}
		}

		tracerId := time.Now().Format("20060102150405")
		b := make([]byte, 6)
		_, err = rand.Read(b)
		if err == nil {
			tracerId = fmt.Sprintf("%s_%x", tracerId, b)
		}

		nodes, err := client.CoreV1().Nodes().List(context.TODO(), metaV1.ListOptions{})
		if err != nil {
			contextLogger.Fatalf("Error in listing nodes: %q", err)
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		failure := make(chan string)

		postProcess := utils.NewPostProcess(&utils.PostProcessConfig{
			Flows:         len(nodes.Items),
			OutStream:     os.Stdout,
			ErrStream:     os.Stderr,
			SkipFirstLine: params.OutputMode != utils.OutputModeJson, // skip first line if json is not used
			Transform:     transform,
		})

		// There is a name difference between the gadget and the bcc tool for this one.
		if subCommand == "capabilities" {
			subCommand = "capable"
		}

		for i, node := range nodes.Items {
			if params.Node != "" && node.Name != params.Node {
				continue
			}
			go func(nodeName string, index int) {
				cmd := fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid %s --tool-mode %s --gadget %s %s %s %s %s %s -- %s",
					tracerId, toolMode, subCommand, labelFilter, namespaceFilter, podnameFilter, containernameFilter, extraParams, gadgetParams)
				var err error
				if subCommand != "tcptop" {
					err = utils.ExecPod(client, nodeName, cmd,
						postProcess.OutStreams[index], postProcess.ErrStreams[index])
				} else {
					err = utils.ExecPod(client, nodeName, cmd, os.Stdout, os.Stderr)
				}
				if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
					failure <- fmt.Sprintf("Error running command: %v\n", err)
				}
			}(node.Name, i) // node.Name is invalidated by the above for loop, causes races
		}

		select {
		case <-sigs:
			if params.OutputMode != utils.OutputModeJson {
				fmt.Println("\nTerminating...")
			}
		case e := <-failure:
			fmt.Printf("\n%s\n", e)
		}

		// remove tracers from the nodes
		for _, node := range nodes.Items {
			if params.Node != "" && node.Name != params.Node {
				continue
			}
			// ignore errors, there is nothing the user can do about it
			utils.ExecPodCapture(client, node.Name,
				fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid %s --stop", tracerId))
		}
		fmt.Printf("\n")
	}
}
