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
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
)

var processCollectorCmd = &cobra.Command{
	Use:   "process-collector",
	Short: "Collect processes",
	Run:   collectorCmdRun("process-collector"),
}

var (
	collectorParamLabel         string
	collectorParamNode          string
	collectorParamPodname       string
	collectorParamContainername string
	collectorParamAllNamespaces bool
	collectorParamJsonOutput    bool
	collectorParamThreads       bool
)

const (
	GADGET_OPERATION = "gadget.kinvolk.io/operation"
)

func init() {
	commands := []*cobra.Command{
		processCollectorCmd,
	}

	// Add flags for all collector gadgets
	for _, command := range commands {
		rootCmd.AddCommand(command)
		command.PersistentFlags().StringVarP(
			&collectorParamLabel,
			"selector",
			"l",
			"",
			fmt.Sprintf("Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2)."),
		)

		command.PersistentFlags().StringVar(
			&collectorParamNode,
			"node",
			"",
			fmt.Sprintf("Show only data from pods running in that node"),
		)

		command.PersistentFlags().StringVarP(
			&collectorParamPodname,
			"podname",
			"p",
			"",
			fmt.Sprintf("Show only data from pods with that name"),
		)

		command.PersistentFlags().StringVarP(
			&collectorParamContainername,
			"containername",
			"c",
			"",
			fmt.Sprintf("Show only data from containers with that name"),
		)

		command.PersistentFlags().BoolVarP(
			&collectorParamAllNamespaces,
			"all-namespaces",
			"A",
			false,
			fmt.Sprintf("Show data from pods in all namespaces"),
		)
		command.PersistentFlags().BoolVarP(
			&collectorParamJsonOutput,
			"json",
			"j",
			false,
			fmt.Sprintf("Output the processes in json format"),
		)
	}

	processCollectorCmd.PersistentFlags().BoolVarP(
		&collectorParamThreads,
		"threads",
		"t",
		false,
		fmt.Sprintf("Show all threads"),
	)
}

func init() {
	gadgetv1alpha1.AddToScheme(scheme.Scheme)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

func deleteTraces(contextLogger *log.Entry, traceRestClient *restclient.RESTClient, traceID string) {
	var listTracesOptions = metav1.ListOptions{
		LabelSelector: fmt.Sprintf("trace-template-hash=%s", traceID),
		FieldSelector: fields.Everything().String(),
	}
	err := traceRestClient.
		Delete().
		Namespace("gadget").
		Resource("traces").
		VersionedParams(&listTracesOptions, scheme.ParameterCodec).
		Do(context.TODO()).
		Error()
	if contextLogger != nil && err != nil {
		contextLogger.Warningf("Error deleting traces: %q", err)
	}
}

func collectorCmdRun(subCommand string) func(*cobra.Command, []string) {
	return func(cmd *cobra.Command, args []string) {
		contextLogger := log.WithFields(log.Fields{
			"command": fmt.Sprintf("kubectl-gadget %s", subCommand),
			"args":    args,
		})

		traceID := randomTraceID()

		client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
		if err != nil {
			contextLogger.Fatalf("Error in creating setting up Kubernetes client: %q", err)
		}

		labelsSelector := map[string]string{}
		if collectorParamLabel != "" {
			pairs := strings.Split(collectorParamLabel, ",")
			for _, pair := range pairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					contextLogger.Fatalf("labels should be a comma-separated list of key-value pairs (key=value[,key=value,...])\n")
				}
				labelsSelector[kv[0]] = kv[1]
			}
		}

		namespace := ""
		if !collectorParamAllNamespaces {
			namespace, _, _ = KubernetesConfigFlags.ToRawKubeConfigLoader().Namespace()
		}

		nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			contextLogger.Fatalf("Error in listing nodes: %q", err)
		}

		restConfig, err := kubeRestConfig()
		if err != nil {
			contextLogger.Fatalf("Error while getting rest config: %s", err)
		}

		traceConfig := *restConfig
		traceConfig.ContentConfig.GroupVersion = &gadgetv1alpha1.GroupVersion
		traceConfig.APIPath = "/apis"
		traceConfig.NegotiatedSerializer = serializer.NewCodecFactory(scheme.Scheme)
		traceConfig.UserAgent = restclient.DefaultKubernetesUserAgent()

		traceRestClient, err := restclient.UnversionedRESTClientFor(&traceConfig)

		for _, node := range nodes.Items {
			if collectorParamNode != "" && node.Name != collectorParamNode {
				continue
			}

			trace := &gadgetv1alpha1.Trace{
				ObjectMeta: metav1.ObjectMeta{
					GenerateName: subCommand + "-",
					Namespace:    "gadget",
					Annotations: map[string]string{
						GADGET_OPERATION: "start",
					},
					Labels: map[string]string{
						"trace-template-hash": traceID,
					},
				},
				Spec: gadgetv1alpha1.TraceSpec{
					Node:   node.Name,
					Gadget: subCommand,
					Filter: &gadgetv1alpha1.ContainerFilter{
						Namespace:     namespace,
						Podname:       collectorParamPodname,
						ContainerName: collectorParamContainername,
						Labels:        labelsSelector,
					},
					RunMode:    "Manual",
					OutputMode: "Status",
				},
			}

			err = traceRestClient.
				Post().
				Namespace(trace.ObjectMeta.Namespace).
				Resource("traces").
				Body(trace).
				Do(context.TODO()).
				Error()
			if err != nil {
				deleteTraces(nil, traceRestClient, traceID)
				contextLogger.Fatalf("Error creating trace on node %s: %q", node.Name, err)
			}
		}

		var listTracesOptions = metav1.ListOptions{
			LabelSelector: fmt.Sprintf("trace-template-hash=%s", traceID),
			FieldSelector: fields.Everything().String(),
		}

		// Wait until results are ready and fetch all results
		// TODO: use a watcher to avoid looping client-side
		//
		// watch, err := traceRestClient.
		//	Get().
		//	Namespace("gadget").
		//	Resource("traces").
		//	VersionedParams(&listTracesOptions, scheme.ParameterCodec).
		//	Watch(context.TODO())
		// if err != nil {
		//	contextLogger.Fatalf("Error waiting for traces: %q", err)
		// }
		// for event := range watch.ResultChan() {
		//	fmt.Printf("Event: %v\n", event)
		//	if data, ok := event.Object.(*metav1.Status); ok {
		//		contextLogger.Infof("watcher status: %s", data.Message)
		//	} else if t, ok := event.Object.(*gadgetv1alpha1.Trace); ok {
		//		fmt.Printf("Got: %v\n", t)
		//	} else {
		//		contextLogger.Fatalf("Error waiting for traces: got unexpected %v", event)
		//	}
		// }

		var results gadgetv1alpha1.TraceList
		start := time.Now()
	RetryLoop:
		for {
			results = gadgetv1alpha1.TraceList{}
			err = traceRestClient.
				Get().
				Namespace("gadget").
				Resource("traces").
				VersionedParams(&listTracesOptions, scheme.ParameterCodec).
				Do(context.TODO()).
				Into(&results)
			if err != nil {
				deleteTraces(contextLogger, traceRestClient, traceID)
				contextLogger.Fatalf("Error getting traces: %q", err)
			}

			timeout := time.Now().Sub(start) > 2*time.Second
			successNodeCount := 0
			nodeErrors := make(map[string]string)
			for _, i := range results.Items {
				if i.Status.State == "Completed" {
					successNodeCount++
				} else {
					if timeout {
						nodeErrors[i.Spec.Node] = i.Status.OperationError
						continue
					}
					time.Sleep(100 * time.Millisecond)
					continue RetryLoop
				}
			}
			for node, err := range nodeErrors {
				contextLogger.Warningf("Error getting traces from node %q: %s", node, err)
			}
			if successNodeCount == 0 {
				deleteTraces(contextLogger, traceRestClient, traceID)
				contextLogger.Fatalf("Error getting traces from all nodes")
			}
			break RetryLoop
		}

		deleteTraces(contextLogger, traceRestClient, traceID)

		// Display results
		type Process struct {
			Tgid                int    `json:"tgid,omitempty"`
			Pid                 int    `json:"pid,omitempty"`
			Comm                string `json:"comm,omitempty"`
			KubernetesNamespace string `json:"kubernetes_namespace,omitempty"`
			KubernetesPod       string `json:"kubernetes_pod,omitempty"`
			KubernetesContainer string `json:"kubernetes_container,omitempty"`
		}
		var allProcesses []Process

		for _, i := range results.Items {
			var processes []Process
			json.Unmarshal([]byte(i.Status.Output), &processes)
			allProcesses = append(allProcesses, processes...)
		}
		if !collectorParamThreads {
			var allProcessesTrimmed []Process
			for _, i := range allProcesses {
				if i.Tgid == i.Pid {
					allProcessesTrimmed = append(allProcessesTrimmed, i)
				}
			}
			allProcesses = allProcessesTrimmed
		}

		sort.Slice(allProcesses, func(i, j int) bool {
			pi, pj := allProcesses[i], allProcesses[j]
			switch {
			case pi.KubernetesNamespace != pj.KubernetesNamespace:
				return pi.KubernetesNamespace < pj.KubernetesNamespace
			case pi.KubernetesPod != pj.KubernetesPod:
				return pi.KubernetesPod < pj.KubernetesPod
			case pi.KubernetesContainer != pj.KubernetesContainer:
				return pi.KubernetesContainer < pj.KubernetesContainer
			case pi.Comm != pj.Comm:
				return pi.Comm < pj.Comm
			case pi.Tgid != pj.Tgid:
				return pi.Tgid < pj.Tgid
			default:
				return pi.Pid < pj.Pid

			}
		})
		if collectorParamJsonOutput {
			b, err := json.MarshalIndent(allProcesses, "", "  ")
			if err != nil {
				contextLogger.Fatalf("Error marshalling results: %s", err)
			}
			fmt.Printf("%s\n", b)
		} else {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)
			if collectorParamThreads {
				fmt.Fprintln(w, "NAMESPACE\tPOD\tCONTAINER\tCOMM\tTGID\tPID\t")
				for _, p := range allProcesses {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t\n",
						p.KubernetesNamespace,
						p.KubernetesPod,
						p.KubernetesContainer,
						p.Comm,
						p.Tgid,
						p.Pid,
					)
				}
			} else {
				fmt.Fprintln(w, "NAMESPACE\tPOD\tCONTAINER\tCOMM\tPID\t")
				for _, p := range allProcesses {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t\n",
						p.KubernetesNamespace,
						p.KubernetesPod,
						p.KubernetesContainer,
						p.Comm,
						p.Pid,
					)
				}
			}
			w.Flush()
		}
	}
}
