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
	displayResults func(contextLogger *log.Entry, nodes *corev1.NodeList, results *gadgetv1alpha1.TraceList),
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

	for _, node := range nodes.Items {
		if params.Node != "" && node.Name != params.Node {
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
					Podname:       params.Podname,
					ContainerName: params.Containername,
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
			if i.Status.State == "Completed" || i.Status.State == "Started" {
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

	if displayResults == nil {
		genericStreamsDisplay(contextLogger, client, params, &results, transformLine)
	} else {
		displayResults(contextLogger, nodes, &results)
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
