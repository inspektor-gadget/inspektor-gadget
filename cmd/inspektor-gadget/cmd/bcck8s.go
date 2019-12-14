package cmd

import (
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
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var execsnoopCmd = &cobra.Command{
	Use:               "execsnoop",
	Short:             "Trace new processes",
	Run:               bccCmd("execsnoop", "execsnoop-ig"),
	PersistentPreRunE: doesKubeconfigExist,
}

var opensnoopCmd = &cobra.Command{
	Use:               "opensnoop",
	Short:             "Trace files",
	Run:               bccCmd("opensnoop", "opensnoop-ig"),
	PersistentPreRunE: doesKubeconfigExist,
}

var tcptopCmd = &cobra.Command{
	Use:               "tcptop",
	Short:             "Show the TCP traffic in a pod",
	Run:               bccCmd("tcptop", "tcptop-edge"),
	PersistentPreRunE: doesKubeconfigExist,
}

var hintsNetworkCmd = &cobra.Command{
	Use:               "tcpconnect",
	Short:             "Suggest Kubernetes Network Policies",
	Run:               bccCmd("tcpconnect", "tcpconnect"),
	PersistentPreRunE: doesKubeconfigExist,
}

var capabilitiesCmd = &cobra.Command{
	Use:               "capabilities",
	Short:             "Suggest Security Capabilities for securityContext",
	Run:               bccCmd("capabilities", "capable-edge"),
	PersistentPreRunE: doesKubeconfigExist,
}

var (
	labelParam     string
	nodeParam      string
	namespaceParam string
	podnameParam   string

	stackFlag   bool
	verboseFlag bool
)

func init() {
	commands := []*cobra.Command{execsnoopCmd, opensnoopCmd, tcptopCmd, hintsNetworkCmd, capabilitiesCmd}
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
	capabilitiesCmd.PersistentFlags().BoolVarP(&verboseFlag, "verbose", "", false, "Include non-audit")
}

type postProcess struct {
	nodeName         string
	nodeShort        string
	orig             io.Writer
	firstLine        bool
	firstLinePrinted *uint64
	failure          chan string
}

func (post postProcess) Write(p []byte) (n int, err error) {
	prefix := "[" + post.nodeShort + "] "
	asStr := string(p)
	lineBreakPos := strings.Index(asStr, "\n")
	if post.firstLine && lineBreakPos > -1 {
		// failures could be detected and propagates here with strings.Contains(asStr, "error") and then post.failure <- asStr
		if atomic.AddUint64(post.firstLinePrinted, 1) > 1 {
			asStr = asStr[lineBreakPos:]
		} else {
			prefix = "NODE "
		}
		post.firstLine = false
	}
	if asStr != "" && asStr != "\n" {
		asStr = "\n" + strings.Trim(asStr, "\n")
		asStr = strings.ReplaceAll(asStr, "\n", "\n"+prefix)
		if !post.firstLine {
			fmt.Fprintf(post.orig, "%s", asStr)
		}
	}
	return len(p), nil
}

func bccCmd(subCommand, bccScript string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"command": fmt.Sprintf("inspektor-gadget %s", subCommand),
			"args":    args,
		})

		client, err := k8sutil.NewClientset(viper.GetString("kubeconfig"))
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		var listOptions = metaV1.ListOptions{
			LabelSelector: labels.Everything().String(),
			FieldSelector: fields.Everything().String(),
		}

		nodes, err := client.CoreV1().Nodes().List(listOptions)
		if err != nil {
			contextLogger.Fatalf("Error in listing nodes: %q", err)
		}

		// tcptop only works on one pod at a time
		if subCommand == "tcptop" {
			if nodeParam == "" || namespaceParam == "" || podnameParam == "" {
				contextLogger.Fatalf("tcptop only works with --node, --namespace and --podname")
			}
		}

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		failure := make(chan string)
		var firstLinePrinted uint64
		tmpId := time.Now().Format("20060102150405")

		fmt.Printf("Node numbers:")
		for i, node := range nodes.Items {
			if nodeParam != "" && node.Name != nodeParam {
				continue
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
			stackArg := ""
			if stackFlag && subCommand == "capabilities" {
				stackArg = "-K"
			}
			verboseArg := ""
			if verboseFlag && subCommand == "capabilities" {
				verboseArg = "-v"
			}
			id := strconv.Itoa(i)
			fmt.Printf(" %s = %s", id, node.Name)
			go func(nodeName string, id string) {
				postOut := postProcess{nodeName, " " + id, os.Stdout, true, &firstLinePrinted, failure}
				postErr := postProcess{nodeName, "E" + id, os.Stderr, false, &firstLinePrinted, failure}
				cmd := fmt.Sprintf("echo $$ > /run/%s.pid && export TERM=xterm-256color && /opt/bcck8s/ensure-flatcar-edge && exec /opt/bcck8s/%s %s %s %s %s %s ",
					tmpId, bccScript, labelFilter, namespaceFilter, podnameFilter, stackArg, verboseArg)
				var err error
				if subCommand != "tcptop" {
					err = execPod(client, nodeName, cmd, postOut, postErr)
				} else {
					err = execPod(client, nodeName, cmd, os.Stdout, os.Stderr)
				}
				if fmt.Sprintf("%s", err) != "command terminated with exit code 137" {
					failure <- fmt.Sprintf("Error in running command: %q\n", err)
				}
			}(node.Name, id) // node.Name is invalidated by the above for loop, causes races
		}

		select {
		case <-sigs:
		case e := <-failure:
			fmt.Printf("\nError detected: %q", e)
		}
		for _, node := range nodes.Items {
			if nodeParam != "" && node.Name != nodeParam {
				continue
			}
			_, _, err := execPodCapture(client, node.Name,
				fmt.Sprintf("touch /run/%s.pid; kill -9 $(cat /run/%s.pid); rm /run/%s.pid",
					tmpId, tmpId, tmpId))
			if err != nil {
				fmt.Printf("Error in running command: %q\n", err)
			}
		}
		fmt.Printf("\n")
	}
}
