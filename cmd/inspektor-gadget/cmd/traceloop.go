package cmd

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

var traceloopCmd = &cobra.Command{
	Use:               "traceloop",
	Short:             "Get strace-like logs of a pod from the past",
	PersistentPreRunE: doesKubeconfigExist,
}

var traceloopListCmd = &cobra.Command{
	Use:   "list",
	Short: "list possible traces",
	Run:   runTraceloopList,
}

var traceloopShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show one trace",
	Run:   runTraceloopShow,
}

var traceloopCloseCmd = &cobra.Command{
	Use:   "close",
	Short: "close one trace",
	Run:   runTraceloopClose,
}

func init() {
	rootCmd.AddCommand(traceloopCmd)
	traceloopCmd.AddCommand(traceloopListCmd)
	traceloopCmd.AddCommand(traceloopShowCmd)
	traceloopCmd.AddCommand(traceloopCloseCmd)
}

func runTraceloopList(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget traceloop list",
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

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "NODE\tTRACES\t")

	for _, node := range nodes.Items {
		line := fmt.Sprintf("%s\t%s\t", node.Name, execPodSimple(client, node.Name, `curl --silent --unix-socket /run/traceloop.socket 'http://localhost/list' | strings | sed 's/[0-9]*: \[\(.*\)\] .*$/\1/' | tr '\n' ' ' `))
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

func runTraceloopShow(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget traceloop show",
		"args":    args,
	})

	if len(args) != 1 {
		contextLogger.Fatalf("Missing parameter: trace name")
	}

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

	for _, node := range nodes.Items {
		if !strings.HasPrefix(args[0], node.Status.Addresses[0].Address+"_") {
			continue
		}
		fmt.Printf("%s", execPodSimple(client, node.Name,
			fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/dump-by-name?name=%s' ; echo`, args[0])))
	}
}

func runTraceloopClose(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget traceloop close",
		"args":    args,
	})

	if len(args) != 1 {
		contextLogger.Fatalf("Missing parameter: trace name")
	}

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

	for _, node := range nodes.Items {
		if !strings.HasPrefix(args[0], node.Status.Addresses[0].Address+"_") {
			continue
		}
		fmt.Printf("%s", execPodSimple(client, node.Name,
			fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/close-by-name?name=%s' ; echo`, args[0])))
	}

}
