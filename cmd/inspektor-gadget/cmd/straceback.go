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

var stracebackCmd = &cobra.Command{
	Use:               "straceback",
	Short:             "Get strace-like logs of a pod from the past",
	PersistentPreRunE: doesKubeconfigExist,
}

var stracebackListCmd = &cobra.Command{
	Use:   "list",
	Short: "list possible traces",
	Run:   runStracebackList,
}

var stracebackShowCmd = &cobra.Command{
	Use:   "show",
	Short: "show one trace",
	Run:   runStracebackShow,
}

var stracebackCloseCmd = &cobra.Command{
	Use:   "close",
	Short: "close one trace",
	Run:   runStracebackClose,
}

func init() {
	rootCmd.AddCommand(stracebackCmd)
	stracebackCmd.AddCommand(stracebackListCmd)
	stracebackCmd.AddCommand(stracebackShowCmd)
	stracebackCmd.AddCommand(stracebackCloseCmd)
}

func runStracebackList(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget straceback list",
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
		line := fmt.Sprintf("%s\t%s\t", node.Name, execPodQuick(client, node.Name, `curl --silent --unix-socket /run/straceback.socket 'http://localhost/list' | strings | sed 's/[0-9]*: \[\(.*\)\] .*$/\1/' | tr '\n' ' ' `))
		fmt.Fprintln(w, line)
	}
	w.Flush()
}

func runStracebackShow(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget straceback show",
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
		fmt.Printf("%s", execPodQuick(client, node.Name,
			fmt.Sprintf(`curl --silent --unix-socket /run/straceback.socket 'http://localhost/dump-by-name?name=%s' ; echo`, args[0])))
	}
}

func runStracebackClose(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget straceback close",
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
		fmt.Printf("%s", execPodQuick(client, node.Name,
			fmt.Sprintf(`curl --silent --unix-socket /run/straceback.socket 'http://localhost/close-by-name?name=%s' ; echo`, args[0])))
	}

}
