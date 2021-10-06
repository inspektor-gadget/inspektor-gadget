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

package utils

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	restclient "k8s.io/client-go/rest"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

const (
	GADGET_OPERATION = "gadget.kinvolk.io/operation"
	traceTimeout     = 2 * time.Second
)

func init() {
	// The Trace REST client needs to know the Trace CRD
	gadgetv1alpha1.AddToScheme(scheme.Scheme)

	// useful for randomTraceID()
	rand.Seed(time.Now().UnixNano())
}

func randomTraceID() string {
	output := make([]byte, 16)
	allowedCharacters := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range output {
		output[i] = allowedCharacters[rand.Int31n(int32(len(allowedCharacters)))]
	}
	return string(output)
}

// If all the elements in the map have the same value, it is returned.
// Otherwise, an empty string is returned.
func getIdenticalValue(m map[string]string) string {
	value := ""
	for _, v := range m {
		if value == "" {
			value = v
		} else if value != v {
			return ""
		}
	}
	return value
}

// If there are more than one element in the map and all the Error/Warning
// are the same, printTraceFeedback will print it only once.
func printTraceFeedback(f func(format string, args ...interface{}), m map[string]string) {
	// Do not print `len(m)` times the same message if it's the same from all nodes
	if len(m) > 1 {
		value := getIdenticalValue(m)
		if value != "" {
			f("Failed to run the gadget on all nodes: %s", value)
			return
		}
	}

	for node, msg := range m {
		f("Failed to run the gadget on node %q: %s", node, msg)
	}
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

func GenericTraceCommand(
	subCommand string,
	params *CommonFlags,
	args []string,
	outputMode string,
	customResultsDisplay func(contextLogger *log.Entry, nodes *corev1.NodeList, results *gadgetv1alpha1.TraceList),
	transformLine func(string) string,
) {

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
	if params.Label != "" {
		pairs := strings.Split(params.Label, ",")
		for _, pair := range pairs {
			kv := strings.Split(pair, "=")
			if len(kv) != 2 {
				contextLogger.Fatalf("labels should be a comma-separated list of key-value pairs (key=value[,key=value,...])\n")
			}
			labelsSelector[kv[0]] = kv[1]
		}
	}

	namespace := ""
	if !params.AllNamespaces {
		namespace = GetNamespace()
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
	if err != nil {
		contextLogger.Fatalf("Error while getting trace rest client: %s", err)
	}

	nodeFound := false
	for _, node := range nodes.Items {
		if params.Node != "" && node.Name != params.Node {
			continue
		}
		nodeFound = true

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
					Podname:       params.Podname,
					ContainerName: params.Containername,
					Labels:        labelsSelector,
				},
				RunMode:    "Manual",
				OutputMode: outputMode,
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

	if params.Node != "" && !nodeFound {
		contextLogger.Fatalf("Invalid filter: Node %q does not exist", params.Node)
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

		timeout := time.Since(start) > traceTimeout
		successNodeCount := 0
		nodeErrors := make(map[string]string)
		nodeWarnings := make(map[string]string)
		for _, i := range results.Items {
			if i.Status.State == "Completed" || i.Status.State == "Started" {
				if i.Status.Output == "" && i.Spec.OutputMode == "Status" {
					// Ignoring empty outputs allows us to show an error instead of
					// an empty list when none of the traces generate an output.
					// This is particularly useful for gadgets like socket-collector
					// where an empty list could be misunderstood.
					continue
				}
				successNodeCount++
			} else {
				if timeout {
					if i.Status.OperationError != "" {
						nodeErrors[i.Spec.Node] = i.Status.OperationError
					}
					if i.Status.OperationWarning != "" {
						nodeWarnings[i.Spec.Node] = i.Status.OperationWarning
					}

					// Consider Trace as timed out if it neither moved the state forward
					// nor notified of an error or warning within the time window.
					if i.Status.OperationError == "" && i.Status.OperationWarning == "" {
						nodeErrors[i.Spec.Node] = fmt.Sprintf("No results received from trace within %v",
							traceTimeout)
					}
					continue
				}

				time.Sleep(100 * time.Millisecond)
				continue RetryLoop
			}
		}

		// Don't print warnings if at least one node succeeded. This avoids showing
		// warnings together with the actual output generated by other nodes.
		if successNodeCount == 0 {
			printTraceFeedback(contextLogger.Warningf, nodeWarnings)
		}

		// Print errors even if other nodes succeeded.
		printTraceFeedback(contextLogger.Errorf, nodeErrors)

		if successNodeCount == 0 {
			deleteTraces(contextLogger, traceRestClient, traceID)
			contextLogger.Fatalf("Failed to run the gadget on all nodes: None of them succeeded")
		}
		break RetryLoop
	}

	if customResultsDisplay == nil {
		if outputMode != "Stream" {
			panic(fmt.Errorf("OutputMode=%q needs a custom display function", outputMode))
		}
		genericStreamsDisplay(contextLogger, client, params, &results, transformLine)
	} else {
		customResultsDisplay(contextLogger, nodes, &results)
	}
	deleteTraces(contextLogger, traceRestClient, traceID)
}

func genericStreamsDisplay(
	contextLogger *log.Entry,
	client *kubernetes.Clientset,
	params *CommonFlags,
	results *gadgetv1alpha1.TraceList,
	transformLine func(string) string,
) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	completion := make(chan string)

	callback := func(line string) string {
		if params.JsonOutput {
			return line
		}
		return transformLine(line)
	}
	postProcess := NewPostProcess(len(results.Items), os.Stdout, os.Stderr, params, callback)

	streamCount := int32(0)
	for index, i := range results.Items {
		if params.Node != "" && i.Spec.Node != params.Node {
			continue
		}
		atomic.AddInt32(&streamCount, 1)
		go func(nodeName, namespace, name string, index int) {
			cmd := fmt.Sprintf("exec gadgettracermanager -call receive-stream -tracerid trace_%s_%s",
				namespace, name)
			err := ExecPod(client, nodeName, cmd,
				postProcess.OutStreams[index], postProcess.ErrStreams[index])
			if err == nil {
				completion <- fmt.Sprintf("Trace completed on node %s\n", nodeName)
			} else {
				completion <- fmt.Sprintf("Error running command on node %s: %v\n", nodeName, err)
			}
		}(i.Spec.Node, i.ObjectMeta.Namespace, i.ObjectMeta.Name, index)
	}

	for {
		select {
		case <-sigs:
			if !params.JsonOutput {
				fmt.Println("\nTerminating...")
			}
			return
		case msg := <-completion:
			fmt.Printf("%s", msg)
			if atomic.AddInt32(&streamCount, -1) == 0 {
				return
			}
		}
	}
}
