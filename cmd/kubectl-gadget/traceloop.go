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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/docker/go-units"
	"github.com/syndtr/gocapability/capability"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/kinvolk/traceloop/pkg/tracemeta"
)

var traceloopCmd = &cobra.Command{
	Use:   "traceloop",
	Short: "Get strace-like logs of a pod from the past",
}

var traceloopListCmd = &cobra.Command{
	Use:   "list",
	Short: "list possible traces",
	Run:   runTraceloopList,
}

var traceloopStartCmd = &cobra.Command{
	Use:   "start",
	Short: "start traceloop",
	Run:   runTraceloopStart,
}

var traceloopStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "stop traceloop",
	Run:   runTraceloopStop,
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

var (
	optionListFull          bool
	optionListAllNamespaces bool
	optionListNoHeaders     bool
)

func init() {
	rootCmd.AddCommand(traceloopCmd)
	traceloopCmd.AddCommand(traceloopStartCmd)
	traceloopCmd.AddCommand(traceloopStopCmd)
	traceloopCmd.AddCommand(traceloopListCmd)
	traceloopCmd.AddCommand(traceloopShowCmd)
	traceloopCmd.AddCommand(traceloopPodCmd)
	traceloopCmd.AddCommand(traceloopCloseCmd)

	traceloopListCmd.PersistentFlags().BoolVarP(
		&optionListFull,
		"full", "f",
		false,
		"show all fields without truncating")

	traceloopListCmd.PersistentFlags().BoolVarP(
		&optionListAllNamespaces,
		"all-namespaces", "A",
		false,
		"if present, list the traces across all namespaces.")

	traceloopListCmd.PersistentFlags().BoolVarP(
		&optionListNoHeaders,
		"no-headers", "",
		false,
		"don't print headers.")
}

const (
	traceloopStateAnnotation = "traceloop.kinvolk.io/state"
)

func getTracesListPerNode(client *kubernetes.Clientset) (out map[string][]tracemeta.TraceMeta, err error) {
	listOptions := metav1.ListOptions{
		LabelSelector: "k8s-app=gadget",
	}
	pods, err := client.CoreV1().Pods("kube-system").List(context.TODO(), listOptions)
	if err != nil {
		return nil, fmt.Errorf("Cannot find gadget pods: %q", err)
	}
	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("No gadget pods found")
	}

	out = map[string][]tracemeta.TraceMeta{}

	validGadgetCount := 0
	for _, pod := range pods.Items {
		if pod.ObjectMeta.Annotations == nil {
			continue
		}

		var tm []tracemeta.TraceMeta
		state := pod.ObjectMeta.Annotations[traceloopStateAnnotation]
		if state == "" {
			continue
		}

		validGadgetCount++

		err := json.Unmarshal([]byte(state), &tm)
		if err != nil {
			fmt.Printf("%v:\n%s\n", err, state)
			continue
		}
		out[pod.Spec.NodeName] = tm
	}

	if validGadgetCount == 0 {
		err = fmt.Errorf("Traceloop is not running on any node. Please start it with 'kubectl gadget traceloop start'.")
	}

	return
}

func capDecode(caps uint64) (out string) {
	for _, c := range capability.List() {
		if (caps & (1 << uint(c))) != 0 {
			out += c.String() + ","
		}
	}
	out = strings.TrimSuffix(out, ",")
	return
}

func runTraceloopStart(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop start",
		"args":    args,
	})

	traces, err := utils.ListTracesByGadgetName("traceloop")
	if err != nil {
		contextLogger.Fatalf("Error checking traces: %v", err)
	}

	if len(traces) != 0 {
		contextLogger.Fatalf("traceloop already running. Run 'kubectl gadget traceloop stop' before.")
	}

	// Create traceloop trace
	_, err = utils.CreateTrace(&utils.TraceConfig{
		GadgetName:      "traceloop",
		Operation:       "start",
		TraceOutputMode: "ExternalResource",
		CommonFlags:     &params,
	})
	if err != nil {
		contextLogger.Fatalf("Error creating trace: %v\n", err)
	}
}

func runTraceloopStop(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop stop",
		"args":    args,
	})
	err := utils.DeleteTracesByGadgetName("traceloop")
	if err != nil {
		contextLogger.Fatalf("Error removing traces: %v\n", err)
	}
}

func runTraceloopList(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop list",
		"args":    args,
	})

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
	}

	tracesPerNode, err := getTracesListPerNode(client)
	if err != nil {
		contextLogger.Fatalf("Error in getting traces: %q", err)
	}

	var traces []tracemeta.TraceMeta
	for _, tm := range tracesPerNode {
		traces = append(traces, tm...)
	}
	sort.SliceStable(traces, func(i, j int) bool {
		if traces[i].Namespace != traces[j].Namespace {
			return traces[i].Namespace < traces[j].Namespace
		}
		if traces[i].Podname != traces[j].Podname {
			return traces[i].Podname < traces[j].Podname
		}
		if traces[i].Containeridx != traces[j].Containeridx {
			return traces[i].Containeridx < traces[j].Containeridx
		}
		if traces[i].TimeCreation != traces[j].TimeCreation {
			return traces[i].TimeCreation < traces[j].TimeCreation
		}
		if traces[i].TimeDeletion != traces[j].TimeDeletion {
			return traces[i].TimeDeletion < traces[j].TimeDeletion
		}
		return false
	})

	namespace, _ := utils.GetNamespace()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
	if !optionListNoHeaders {
		if optionListFull {
			fmt.Fprintln(w, "NODE\tNAMESPACE\tPOD\tPODUID\tINDEX\tTRACEID\tCONTAINERID\tSTATUS\tCAPABILITIES\t")
		} else {
			if !optionListAllNamespaces {
				fmt.Fprintln(w, "POD\tPODUID\tINDEX\tTRACEID\tCONTAINERID\tSTATUS\t")
			} else {
				fmt.Fprintln(w, "NAMESPACE\tPOD\tPODUID\tINDEX\tTRACEID\tCONTAINERID\tSTATUS\t")
			}
		}
	}

	for _, trace := range traces {
		if trace.Containeridx == -1 {
			// The pause container
			continue
		}

		if trace.Namespace != namespace && !optionListAllNamespaces {
			continue
		}

		status := ""
		switch trace.Status {
		case "created":
			fallthrough
		case "ready":
			status = "started"
			if t, err := time.Parse(time.RFC3339, trace.TimeCreation); err == nil {
				status += fmt.Sprintf(" %s ago",
					strings.ToLower(units.HumanDuration(time.Now().Sub(t))))
			}
		case "deleted":
			status = "terminated"
			if t, err := time.Parse(time.RFC3339, trace.TimeDeletion); err == nil {
				status += fmt.Sprintf(" %s ago",
					strings.ToLower(units.HumanDuration(time.Now().Sub(t))))
			}
		default:
			status = fmt.Sprintf("unknown (%v)", trace.Status)
		}
		if optionListFull {
			fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\t%v\n", trace.Node, trace.Namespace, trace.Podname, trace.PodUID, trace.Containeridx, trace.TraceID, trace.ContainerID, status, capDecode(trace.Capabilities))
		} else {
			uid := trace.PodUID
			if len(uid) > 8 {
				uid = uid[:8]
			}
			containerID := trace.ContainerID
			containerID = strings.TrimPrefix(containerID, "docker://")
			containerID = strings.TrimPrefix(containerID, "cri-o://")
			if len(containerID) > 8 {
				containerID = containerID[:8]
			}
			if !optionListAllNamespaces {
				fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\n", trace.Podname, uid, trace.Containeridx, trace.TraceID, containerID, status)
			} else {
				fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\t%v\t%v\n", trace.Namespace, trace.Podname, uid, trace.Containeridx, trace.TraceID, containerID, status)
			}
		}
	}
	w.Flush()
}

func runTraceloopShow(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop show",
		"args":    args,
	})

	if len(args) != 1 {
		contextLogger.Fatalf("Missing parameter: trace name")
	}

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
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
				fmt.Printf("%s", utils.ExecPodSimple(client, node,
					fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/dump-by-traceid?traceid=%s' ; echo`, args[0])))
			}
		}
	}
}

func runTraceloopPod(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop pod namespace podname idx",
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

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
	}

	pod, err := client.CoreV1().Pods(namespace).Get(context.TODO(), podname, metav1.GetOptions{})
	if err != nil {
		contextLogger.Fatalf("Cannot get pod %s: %q", podname, err)
	}

	if pod.Spec.NodeName == "" {
		contextLogger.Fatalf("Pod %s not scheduled yet", podname)
	}

	fmt.Printf("%s", utils.ExecPodSimple(client, pod.Spec.NodeName,
		fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/dump-pod?namespace=%s&podname=%s&idx=%s' ; echo`,
			namespace, podname, idx)))
}

func runTraceloopClose(cmd *cobra.Command, args []string) {
	contextLogger := log.WithFields(log.Fields{
		"command": "kubectl-gadget traceloop close",
		"args":    args,
	})

	if len(args) != 1 {
		contextLogger.Fatalf("Missing parameter: trace name")
	}

	client, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
	}

	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		contextLogger.Fatalf("Error in listing nodes: %q", err)
	}

	for _, node := range nodes.Items {
		if !strings.HasPrefix(args[0], node.Status.Addresses[0].Address+"_") {
			continue
		}
		fmt.Printf("%s", utils.ExecPodSimple(client, node.Name,
			fmt.Sprintf(`curl --silent --unix-socket /run/traceloop.socket 'http://localhost/close-by-name?name=%s' ; echo`, args[0])))
	}
}
