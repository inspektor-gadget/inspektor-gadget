package main

import (
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var execsnoopCmd = &cobra.Command{
	Use:               "execsnoop",
	Short:             "Trace new processes",
	Run:               bccCmd("execsnoop", "/usr/share/bcc/tools/execsnoop"),
	PersistentPreRunE: doesKubeconfigExist,
}

var opensnoopCmd = &cobra.Command{
	Use:               "opensnoop",
	Short:             "Trace files",
	Run:               bccCmd("opensnoop", "/usr/share/bcc/tools/opensnoop"),
	PersistentPreRunE: doesKubeconfigExist,
}

var bindsnoopCmd = &cobra.Command{
	Use:               "bindsnoop",
	Short:             "Trace IPv4 and IPv6 bind() system calls",
	Run:               bccCmd("opensnoop", "/usr/share/bcc/tools/bindsnoop"),
	PersistentPreRunE: doesKubeconfigExist,
}

var profileCmd = &cobra.Command{
	Use:               "profile",
	Short:             "Profile CPU usage by sampling stack traces",
	Run:               bccCmd("profile", "/usr/share/bcc/tools/profile"),
	PersistentPreRunE: doesKubeconfigExist,
}

var tcptopCmd = &cobra.Command{
	Use:               "tcptop",
	Short:             "Show the TCP traffic in a pod",
	Run:               bccCmd("tcptop", "/usr/share/bcc/tools/tcptop"),
	PersistentPreRunE: doesKubeconfigExist,
}

var tcpconnectCmd = &cobra.Command{
	Use:               "tcpconnect",
	Short:             "Suggest Kubernetes Network Policies",
	Run:               bccCmd("tcpconnect", "/usr/share/bcc/tools/tcpconnect"),
	PersistentPreRunE: doesKubeconfigExist,
}

var tcptracerCmd = &cobra.Command{
	Use:               "tcptracer",
	Short:             "trace tcp connect, accept and close",
	Run:               bccCmd("tcptracer", "/usr/share/bcc/tools/tcptracer"),
	PersistentPreRunE: doesKubeconfigExist,
}

var capabilitiesCmd = &cobra.Command{
	Use:               "capabilities",
	Short:             "Suggest Security Capabilities for securityContext",
	Run:               bccCmd("capabilities", "/usr/share/bcc/tools/capable"),
	PersistentPreRunE: doesKubeconfigExist,
}

var (
	labelParam     string
	nodeParam      string
	namespaceParam string
	podnameParam   string

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
	args := []string{"label", "node", "namespace", "podname"}
	vars := []*string{&labelParam, &nodeParam, &namespaceParam, &podnameParam}
	for _, command := range commands {
		rootCmd.AddCommand(command)
		for i, _ := range args {
			command.PersistentFlags().StringVar(
				vars[i],
				args[i],
				"",
				fmt.Sprintf("Kubernetes %s selector", args[i]))
		}
	}
	capabilitiesCmd.PersistentFlags().BoolVarP(&stackFlag, "print-stack", "", false, "Print kernel and userspace call stack of cap_capable()")
	capabilitiesCmd.PersistentFlags().BoolVarP(&uniqueFlag, "unique", "", false, "Don't print duplicate capability checks")
	capabilitiesCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "", false, "Include non-audit")

	profileCmd.PersistentFlags().BoolVarP(&profileUser, "user", "U", false, "Show stacks from user space only (no kernel space stacks)")
	profileCmd.PersistentFlags().BoolVarP(&profileKernel, "kernel", "K", false, "Show stacks from kernel space only (no user space stacks)")
}

type postProcess struct {
	firstLinePrinted uint64
	outStreams []*postProcessSingle
	errStreams []*postProcessSingle
}

type postProcessSingle struct {
	nodeShort        string
	orig             io.Writer
	firstLine        bool
	firstLinePrinted *uint64
	buffer           string  // buffer to save incomplete strings
}

func newPostProcess(n int, outStream io.Writer, errStream io.Writer) *postProcess {
	p := &postProcess{
		firstLinePrinted: 0,
		outStreams: make([]*postProcessSingle, n),
		errStreams: make([]*postProcessSingle, n),
	}

	for i := 0; i < n; i++ {
		p.outStreams[i] = &postProcessSingle{
			nodeShort:        " " + strconv.Itoa(i),
			orig:             outStream,
			firstLine:         true,
			firstLinePrinted: &p.firstLinePrinted,
			buffer:           "",
		}

		p.errStreams[i] = &postProcessSingle{
			nodeShort:        "E" + strconv.Itoa(i),
			orig:             errStream,
			firstLine:         false,
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
	for _, line := range lines[0:len(lines)-1] {
		if post.firstLine {
			post.firstLine = false
			if atomic.AddUint64(post.firstLinePrinted, 1) == 1 {
				prefix = "NODE "
			} else {
				continue // ignore this line, somebody else already printed it
			}
		}
		fmt.Fprintf(post.orig, "%s\n", prefix + line)
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

		client, err := k8sutil.NewClientset(viper.GetString("kubeconfig"))
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		// tcptop only works on one pod at a time
		if subCommand == "tcptop" {
			if nodeParam == "" || namespaceParam == "" || podnameParam == "" {
				contextLogger.Fatalf("tcptop only works with --node, --namespace and --podname")
			}
		}

		labelFilter := ""
		if labelParam != "" {
			labelFilter = fmt.Sprintf("--label %q", labelParam)
		}

		namespaceFilter := ""
		if namespaceParam != "" {
			namespaceFilter = fmt.Sprintf("--namespace %q", namespaceParam)
		}

		podnameFilter := ""
		if podnameParam != "" {
			podnameFilter = fmt.Sprintf("--podname %q", podnameParam)
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
				cmd := fmt.Sprintf("exec /opt/bcck8s/bcc-wrapper.sh --flatcaredgeonly --tracerid %s --gadget %s %s %s %s -- %s",
					tracerId, bccScript, labelFilter, namespaceFilter, podnameFilter, gadgetParams)
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
