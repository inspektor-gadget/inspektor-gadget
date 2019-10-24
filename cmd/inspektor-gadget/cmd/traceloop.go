package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/docker/go-units"

	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/kinvolk/inspektor-gadget/pkg/tracemeta"
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

	traceloopListCmd.PersistentFlags().Bool(
		"full",
		false,
		"show full fields without truncating")
	viper.BindPFlag("full", traceloopListCmd.PersistentFlags().Lookup("full"))
}

func getTracesListPerNode(client *kubernetes.Clientset) (out map[string][]tracemeta.TraceMeta, err error) {
	var listOptions = metaV1.ListOptions{
		LabelSelector: "k8s-app=gadget",
		FieldSelector: fields.Everything().String(),
	}
	pods, err := client.CoreV1().Pods("kube-system").List(listOptions)
	if err != nil {
		return nil, fmt.Errorf("Cannot find gadget pods: %q", err)
	}

	out = map[string][]tracemeta.TraceMeta{}

	for _, pod := range pods.Items {
		if pod.ObjectMeta.Annotations == nil {
			continue
		}

		var tm []tracemeta.TraceMeta
		err := json.Unmarshal([]byte(pod.ObjectMeta.Annotations["traceloop.kinvolk.io/state"]), &tm)
		if err != nil {
			fmt.Printf("%v\n", err)
			continue
		}
		out[pod.Spec.NodeName] = tm
	}
	return
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

	tracesPerNode, err := getTracesListPerNode(client)
	if err != nil {
		contextLogger.Fatalf("Error in getting traces: %q", err)
	}

	full := viper.GetBool("full")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	fmt.Fprintln(w, "NODE\tNAMESPACE\tPODNAME\tPODUID\tINDEX\tTRACEID\tCONTAINERID\tSTATUS\t")

	for node, tm := range tracesPerNode {
		for _, trace := range tm {
			status := ""
			switch trace.Status {
			case "created":
				fallthrough
			case "ready":
				t, err := time.Parse(time.RFC3339, trace.TimeCreation)
				if err == nil {
					status = fmt.Sprintf("created %s ago", units.HumanDuration(time.Now().Sub(t)))
				} else {
					status = fmt.Sprintf("created a while ago (%v)", err)
				}
			case "deleted":
				t, err := time.Parse(time.RFC3339, trace.TimeDeletion)
				if err == nil {
					status = fmt.Sprintf("%s %s ago", trace.Status, units.HumanDuration(time.Now().Sub(t)))
				} else {
					status = fmt.Sprintf("%s a while ago (%v)", trace.Status, err)
				}
			default:
				status = fmt.Sprintf("unknown (%v)", trace.Status)
			}
			if full {
				fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n", node, trace.Namespace, trace.Podname, trace.UID, trace.Containeridx, trace.TraceID, trace.ContainerID, status)
			} else {
				uid := trace.UID
				if len(uid) > 8 {
					uid = uid[:8]
				}
				containerID := trace.ContainerID
				containerID = strings.TrimPrefix(containerID, "docker://")
				if len(containerID) > 8 {
					containerID = containerID[:8]
				}
				fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n", node, trace.Namespace, trace.Podname, uid, trace.Containeridx, trace.TraceID, containerID, status)
			}
		}
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

	tracesPerNode, err := getTracesListPerNode(client)
	if err != nil {
		contextLogger.Fatalf("Error in getting traces: %q", err)
	}

	for node, tm := range tracesPerNode {
		for _, trace := range tm {
			if trace.TraceID == args[0] {
				fmt.Printf("%s", execPodSimple(client, node,
					fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/dump-by-traceid?traceid=%s' ; echo`, args[0])))
			}
		}

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
