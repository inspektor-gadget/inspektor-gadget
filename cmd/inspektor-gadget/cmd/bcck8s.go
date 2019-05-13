package cmd

import (
	"fmt"
	"os"
	"os/signal"
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
	Run:               bccCmd("execsnoop", "execsnoop-edge"),
	PersistentPreRunE: doesKubeconfigExist,
}

var opensnoopCmd = &cobra.Command{
	Use:               "opensnoop",
	Short:             "Trace files",
	Run:               bccCmd("opensnoop", "opensnoop-edge"),
	PersistentPreRunE: doesKubeconfigExist,
}

var tcptopCmd = &cobra.Command{
	Use:               "tcptop",
	Short:             "Show the TCP traffic in a pod",
	Run:               bccCmd("tcptop", "tcptop-edge"),
	PersistentPreRunE: doesKubeconfigExist,
}

var hintsNetworkCmd = &cobra.Command{
	Use:               "hints-network",
	Short:             "Suggest Kubernetes Network Policies",
	Run:               bccCmd("hints-network", "tcpconnect"),
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
	insetidFlag bool
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
	capabilitiesCmd.PersistentFlags().BoolVarP(&insetidFlag, "include-insetid", "", false, "Include capability checks with the INSETID bit set")
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
		tmpId := time.Now().Format("20060102150405")

		for _, node := range nodes.Items {
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
			insetidArg := ""
			if !insetidFlag && subCommand == "capabilities" {
				insetidArg = "--no-insetid"
			}
			verboseArg := ""
			if subCommand == "capabilities" {
				verboseArg = "-v"
			}
			err := execPodQuickStart(client, node.Name,
				fmt.Sprintf("sh -c \"echo \\$\\$ > /run/%s.pid && export TERM=xterm-256color && exec /opt/bcck8s/%s %s %s %s %s %s %s \" || true",
					tmpId, bccScript, labelFilter, namespaceFilter, podnameFilter, stackArg, verboseArg, insetidArg))
			if err != "" {
				fmt.Printf("Error in running command: %q\n", err)
			}
		}

		<-sigs
		fmt.Printf("Interrupted!\n")
		for _, node := range nodes.Items {
			if nodeParam != "" && node.Name != nodeParam {
				continue
			}
			err := execPodQuickStart(client, node.Name,
				fmt.Sprintf("sh -c \"touch /run/%s.pid; kill -9 \\$(cat /run/%s.pid); rm /run/%s.pid\"",
					tmpId, tmpId, tmpId))
			if err != "" {
				fmt.Printf("Error in running command: %q\n", err)
			}
		}
	}
}
