package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
)

var execsnoopCmd = &cobra.Command{
	Use:   "execsnoop",
	Short: "Trace new processes",
	Run:   bccCmd("execsnoop", "/usr/share/bcc/tools/execsnoop"),
}

var opensnoopCmd = &cobra.Command{
	Use:   "opensnoop",
	Short: "Trace files",
	Run:   bccCmd("opensnoop", "/usr/share/bcc/tools/opensnoop"),
}

var bindsnoopCmd = &cobra.Command{
	Use:   "bindsnoop",
	Short: "Trace IPv4 and IPv6 bind() system calls",
	Run:   bccCmd("opensnoop", "/usr/share/bcc/tools/bindsnoop"),
}

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Profile CPU usage by sampling stack traces",
	Run:   bccCmd("profile", "/usr/share/bcc/tools/profile"),
}

var tcptopCmd = &cobra.Command{
	Use:   "tcptop",
	Short: "Show the TCP traffic in a pod",
	Run:   bccCmd("tcptop", "/usr/share/bcc/tools/tcptop"),
}

var tcpconnectCmd = &cobra.Command{
	Use:   "tcpconnect",
	Short: "Suggest Kubernetes Network Policies",
	Run:   bccCmd("tcpconnect", "/usr/share/bcc/tools/tcpconnect"),
}

var tcptracerCmd = &cobra.Command{
	Use:   "tcptracer",
	Short: "Trace tcp connect, accept and close",
	Run:   bccCmd("tcptracer", "/usr/share/bcc/tools/tcptracer"),
}

var capabilitiesCmd = &cobra.Command{
	Use:   "capabilities",
	Short: "Suggest Security Capabilities for securityContext",
	Run:   bccCmd("capabilities", "/usr/share/bcc/tools/capable"),
}

var (
	labelParam         string
	nodeParam          string
	podnameParam       string
	containernameParam string
	allNamespaces      bool

	stackFlag   bool
	uniqueFlag  bool
	verboseFlag bool

	profileKernel bool
	profileUser   bool
)

func init() {
	commands := []*cobra.Command{
		execsnoopCmd,
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
		command.PersistentFlags().StringVarP(
			&labelParam,
			"selector",
			"l",
			"",
			fmt.Sprintf("Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2)."),
		)

		command.PersistentFlags().StringVar(
			&nodeParam,
			"node",
			"",
			fmt.Sprintf("Show only events from pods running in that node"),
		)

		command.PersistentFlags().StringVarP(
			&podnameParam,
			"podname",
			"p",
			"",
			fmt.Sprintf("Show only events from pods with that name"),
		)

		command.PersistentFlags().StringVarP(
			&containernameParam,
			"containername",
			"c",
			"",
			fmt.Sprintf("Show only events from containers with that name"),
		)

		command.PersistentFlags().BoolVarP(
			&allNamespaces,
			"all-namespaces",
			"A",
			false,
			fmt.Sprintf("Show events from pods in all namespaces"),
		)
	}

	// Add flags specific to some BCC gadgets
	capabilitiesCmd.PersistentFlags().BoolVarP(&stackFlag, "print-stack", "", false, "Print kernel and userspace call stack of cap_capable()")
	capabilitiesCmd.PersistentFlags().BoolVarP(&uniqueFlag, "unique", "", false, "Don't print duplicate capability checks")
	capabilitiesCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "", false, "Include non-audit")

	profileCmd.PersistentFlags().BoolVarP(&profileUser, "user", "U", false, "Show stacks from user space only (no kernel space stacks)")
	profileCmd.PersistentFlags().BoolVarP(&profileKernel, "kernel", "K", false, "Show stacks from kernel space only (no user space stacks)")
}

type postProcess struct {
	firstLinePrinted uint64
	outStreams       []*postProcessSingle
	errStreams       []*postProcessSingle
}

type postProcessSingle struct {
	nodeShort        string
	orig             io.Writer
	firstLine        bool
	firstLinePrinted *uint64
	buffer           string // buffer to save incomplete strings
}

func newPostProcess(n int, outStream io.Writer, errStream io.Writer) *postProcess {
	p := &postProcess{
		firstLinePrinted: 0,
		outStreams:       make([]*postProcessSingle, n),
		errStreams:       make([]*postProcessSingle, n),
	}

	for i := 0; i < n; i++ {
		p.outStreams[i] = &postProcessSingle{
			nodeShort:        " " + strconv.Itoa(i),
			orig:             outStream,
			firstLine:        true,
			firstLinePrinted: &p.firstLinePrinted,
			buffer:           "",
		}

		p.errStreams[i] = &postProcessSingle{
			nodeShort:        "E" + strconv.Itoa(i),
			orig:             errStream,
			firstLine:        false,
			firstLinePrinted: &p.firstLinePrinted,
			buffer:           "",
		}
	}

	return p
}

func (post *postProcessSingle) Write(p []byte) (n int, err error) {
	prefix := "[" + post.nodeShort + "] "
	asStr := post.buffer + string(p)

	lines := strings.Split(asStr, "\n")
	if len(lines) == 0 {
		return len(p), nil
	}

	// Print lines with prefix but the last one
	for _, line := range lines[0 : len(lines)-1] {
		if post.firstLine {
			post.firstLine = false
			if atomic.AddUint64(post.firstLinePrinted, 1) == 1 {
				prefix = "NODE "
			} else {
				continue // ignore this line, somebody else already printed it
			}
		}
		fmt.Fprintf(post.orig, "%s\n", prefix+line)
	}

	post.buffer = lines[len(lines)-1] // Buffer last line to print in next iteration

	return len(p), nil
}

func bccCmd(subCommand, bccScript string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"command": fmt.Sprintf("kubectl-gadget %s", subCommand),
			"args":    args,
		})

		client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		// tcptop only works on one pod at a time
		if subCommand == "tcptop" {
			if nodeParam == "" || podnameParam == "" {
				contextLogger.Fatalf("tcptop only works with --node and --podname")
			}
		}

		labelFilter := ""
		if labelParam != "" {
			pairs := strings.Split(labelParam, ",")
			for _, pair := range pairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					contextLogger.Fatalf("labels should be a comma-separated list of key-value pairs (key=value[,key=value,...])\n")
				}
			}
			labelFilter = fmt.Sprintf("--label %s", labelParam)
		}

		namespaceFilter := ""
		if !allNamespaces {
			namespace, _, _ := KubernetesConfigFlags.ToRawKubeConfigLoader().Namespace()
			namespaceFilter = fmt.Sprintf("--namespace %s", namespace)
		}

		podnameFilter := ""
		if podnameParam != "" {
			podnameFilter = fmt.Sprintf("--podname %s", podnameParam)
		}

		containernameFilter := ""
		if containernameParam != "" {
			containernameFilter = fmt.Sprintf("--containername %s", containernameParam)
		}

		gadgetParams := ""
		switch subCommand {
		case "capabilities":
			if stackFlag {
				gadgetParams += " -K"
			}
			if uniqueFlag {
				gadgetParams += " --unique"
			}
			if verboseFlag {
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
			tracerId = fmt.Sprintf("%s-%x", tracerId, b)
		}

		var listOptions = metaV1.ListOptions{
			LabelSelector: labels.Everything().String(),
			FieldSelector: fields.Everything().String(),
		}

		nodes, err := client.CoreV1().Nodes().List(listOptions)
		if err != nil {
			contextLogger.Fatalf("Error in listing nodes: %q", err)
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		failure := make(chan string)

		postProcess := newPostProcess(len(nodes.Items), os.Stdout, os.Stderr)

		fmt.Printf("Node numbers:")
		for i, node := range nodes.Items {
			if nodeParam != "" && node.Name != nodeParam {
				continue
			}
			fmt.Printf(" %d = %s", i, node.Name)
			go func(nodeName string, index int) {
				cmd := fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid %s --gadget %s %s %s %s %s -- %s",
					tracerId, bccScript, labelFilter, namespaceFilter, podnameFilter, containernameFilter, gadgetParams)
				var err error
				if subCommand != "tcptop" {
					err = execPod(client, nodeName, cmd,
						postProcess.outStreams[index], postProcess.errStreams[index])
				} else {
					err = execPod(client, nodeName, cmd, os.Stdout, os.Stderr)
				}
				if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
					failure <- fmt.Sprintf("Error running command: %v\n", err)
				}
			}(node.Name, i) // node.Name is invalidated by the above for loop, causes races
		}
		fmt.Println()

		select {
		case <-sigs:
			fmt.Println("\nTerminating...")
		case e := <-failure:
			fmt.Printf("\n%s\n", e)
		}

		// remove tracers from the nodes
		for _, node := range nodes.Items {
			if nodeParam != "" && node.Name != nodeParam {
				continue
			}
			// ignore errors, there is nothing the user can do about it
			execPodCapture(client, node.Name,
				fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --tracerid %s --stop", tracerId))
		}
		fmt.Printf("\n")
	}
}
