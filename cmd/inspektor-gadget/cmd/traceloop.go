package cmd

import (
	"errors"
	"fmt"
	"strings"

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

var traceloopPodCmd = &cobra.Command{
	Use:   "pod",
	Short: "show the traces in one pod",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 3 {
			return errors.New("requires 3 arguments: namespace, pod name and idx")
		}
		return nil
	},
	Run: runTraceloopPod,
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
	traceloopCmd.AddCommand(traceloopPodCmd)
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

	for _, node := range nodes.Items {
		fmt.Printf("%s\n", node.Name)
		fmt.Printf("%s", execPodSimple(client, node.Name, `curl --silent --unix-socket /run/traceloop.socket 'http://localhost/list' | strings`))
	}
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

func runTraceloopPod(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "inspektor-gadget traceloop pod namespace podname idx",
		"args":    args,
	})

	if len(args) < 3 {
		contextLogger.Fatalf("Missing parameter: namespace or podname or idx")
	} else if len(args) > 3 {
		contextLogger.Fatalf("Too many parameters")
	}
	namespace := args[0]
	podname := args[1]
	idx := args[2]

	client, err := k8sutil.NewClientset(viper.GetString("kubeconfig"))
	if err != nil {
		contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
	}

	pod, err := client.CoreV1().Pods(namespace).Get(podname, metaV1.GetOptions{})
	if err != nil {
		contextLogger.Fatalf("Cannot get pod %s: %q", podname, err)
	}

	if pod.Spec.NodeName == "" {
		contextLogger.Fatalf("Pod %s not scheduled yet", podname)
	}

	fmt.Printf("%s", execPodSimple(client, pod.Spec.NodeName,
		fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/dump-pod?namespace=%s&podname=%s&idx=%s' ; echo`,
			namespace, podname, idx)))
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
