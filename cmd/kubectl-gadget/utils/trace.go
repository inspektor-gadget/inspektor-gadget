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
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"

	log "github.com/sirupsen/logrus"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	clientset "github.com/inspektor-gadget/inspektor-gadget/pkg/client/clientset/versioned"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

const (
	GadgetOperation = "gadget.kinvolk.io/operation"
	// We name it "global" as if one trace is created on several nodes, then each
	// copy of the trace on each node will share the same id.
	GlobalTraceID = "global-trace-id"
	TraceTimeout  = 5 * time.Second
)

// TraceConfig is used to contain information used to manage a trace.
type TraceConfig struct {
	// GadgetName is gadget name, e.g. socket-collector.
	GadgetName string

	// GadgetNamespace is the namespace where Inspektor Gadget is deployed
	GadgetNamespace string

	// Operation is the gadget operation to apply to this trace, e.g. start to
	// start the tracing.
	Operation gadgetv1alpha1.Operation

	// TraceOutputMode is the trace output mode, the correct values are:
	// * "Status": The trace prints information when its status changes.
	// * "Stream": The trace prints information as events arrive.
	// * "File": The trace prints information into a file.
	// * "ExternalResource": The trace prints information an external resource,
	// e.g. a seccomp profile.
	TraceOutputMode gadgetv1alpha1.TraceOutputMode

	// TraceOutputState is the state in which the trace can output information.
	// For example, trace for *-collector gadget contains output while in
	// Completed state.
	// But other gadgets, like dns, can contain output only in Started state.
	TraceOutputState gadgetv1alpha1.TraceState

	// TraceOutput is either the name of the file when TraceOutputMode is File or
	// the name of the external resource when TraceOutputMode is ExternalResource.
	// Otherwise, its value is ignored.
	TraceOutput string

	// TraceInitialState is the state in which the trace should be after its
	// creation.
	// This field is only used by "multi-rounds gadgets" like biolatency.
	TraceInitialState gadgetv1alpha1.TraceState

	// CommonFlags is used to hold parameters given on the command line interface.
	CommonFlags *CommonFlags

	// Parameters is used to pass specific gadget configurations.
	Parameters map[string]string

	// AdditionalLabels is used to pass specific labels to traces.
	AdditionalLabels map[string]string
}

// useful for randomTraceID()
var r *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func init() {
	// The Trace REST client needs to know the Trace CRD
	gadgetv1alpha1.AddToScheme(scheme.Scheme)
}

func randomTraceID() string {
	output := make([]byte, 16)
	allowedCharacters := "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	for i := range output {
		output[i] = allowedCharacters[r.Int31n(int32(len(allowedCharacters)))]
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

// If there are more than one element in the map and the Error/Warning is
// the same for all the nodes, printTraceFeedback will print it only once.
func printTraceFeedback(prefix string, m map[string]string, totalNodes int) {
	// Do not print `len(m)` times the same message if it's the same from all nodes
	if len(m) > 1 && len(m) == totalNodes {
		value := getIdenticalValue(m)
		if value != "" {
			fmt.Fprintf(os.Stderr, "%s: %s\n",
				prefix, commonutils.WrapInErrRunGadgetOnAllNode(errors.New(value)))
			return
		}
	}

	for node, msg := range m {
		fmt.Fprintf(os.Stderr, "%s: %s\n",
			prefix, commonutils.WrapInErrRunGadgetOnNode(node, errors.New(msg)))
	}
}

func deleteTraces(gadgetNamespace string, traceClient *clientset.Clientset, traceID string) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", GlobalTraceID, traceID),
	}

	err := traceClient.GadgetV1alpha1().Traces(gadgetNamespace).DeleteCollection(
		context.TODO(), metav1.DeleteOptions{}, listTracesOptions,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: deleting traces: %q", err)
	}
}

func GetTraceClient() (*clientset.Clientset, error) {
	return getTraceClient()
}

func getTraceClient() (*clientset.Clientset, error) {
	config, err := KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("creating RESTConfig: %w", err)
	}

	traceClient, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("setting up trace client: %w", err)
	}

	return traceClient, err
}

func printVersionSkewWarning(pods *corev1.PodList) {
	for _, pod := range pods.Items {
		image := pod.Spec.Containers[0].Image

		parts := strings.Split(image, ":")
		if len(parts) != 2 {
			continue
		}

		versionStr := parts[1]

		// Use 1: to remove the v prefix
		if err := commonutils.CheckServerVersionSkew(versionStr[1:]); err != nil {
			log.Warn(err.Error())
			break
		}
	}
}

// createTraces creates a trace using Kubernetes REST API.
// Note that, this function will create the trace on all existing node if
// trace.Spec.Node is empty.
func createTraces(gadgetNamespace string, trace *gadgetv1alpha1.Trace) error {
	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		return commonutils.WrapInErrSetupK8sClient(err)
	}

	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods(gadgetNamespace).List(context.TODO(), opts)
	if err != nil {
		return commonutils.WrapInErrListPods(err)
	}

	if len(pods.Items) == 0 {
		return fmt.Errorf("no gadget pods found. Is Inspektor Gadget deployed?")
	}

	printVersionSkewWarning(pods)

	traceNode := trace.Spec.Node
	for _, pod := range pods.Items {
		if traceNode != "" && pod.Spec.NodeName != traceNode {
			continue
		}

		ready := false

		for _, c := range pod.Status.Conditions {
			if c.Type == corev1.PodReady {
				ready = c.Status == corev1.ConditionTrue
				break
			}
		}

		if !ready {
			if traceNode != "" {
				return fmt.Errorf("gadget pod on node %q is not ready", pod.Spec.NodeName)
			}

			fmt.Fprintf(os.Stderr, "gadget pod on node %q is not ready", pod.Spec.NodeName)
			continue
		}

		// If no particular node was given, we need to apply this trace on all
		// available nodes.
		if traceNode == "" {
			trace.Spec.Node = pod.Spec.NodeName
		}

		_, err := traceClient.GadgetV1alpha1().Traces(gadgetNamespace).Create(
			context.TODO(), trace, metav1.CreateOptions{},
		)
		if err != nil {
			traceID, present := trace.Labels[GlobalTraceID]
			if present {
				// Clean before exiting!
				deleteTraces(gadgetNamespace, traceClient, traceID)
			}

			return fmt.Errorf("creating trace on node %q: %w", pod.Spec.NodeName, err)
		}
	}

	return nil
}

// updateTraceOperation updates operation for an already existing trace using
// Kubernetes REST API.
func updateTraceOperation(gadgetNamespace string, trace *gadgetv1alpha1.Trace, operation string) error {
	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	// This trace will be used as JSON merge patch to update GADGET_OPERATION,
	// see:
	// https://datatracker.ietf.org/doc/html/rfc6902
	// https://datatracker.ietf.org/doc/html/rfc7386
	type Annotations map[string]string
	type ObjectMeta struct {
		Annotations Annotations `json:"annotations"`
	}
	type JSONMergePatch struct {
		ObjectMeta ObjectMeta `json:"metadata"`
	}
	patch := JSONMergePatch{
		ObjectMeta: ObjectMeta{
			Annotations{
				GadgetOperation: operation,
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshaling the operation annotations: %w", err)
	}

	_, err = traceClient.GadgetV1alpha1().Traces(gadgetNamespace).Patch(
		context.TODO(), trace.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{},
	)

	return err
}

// CreateTrace initializes a trace object with its field according to the given
// parameter.
// The trace is then posted to the RESTClient which returns an error if
// something wrong occurred.
// A unique trace identifier is returned, this identifier will be used as other
// function parameter.
// A trace obtained with this function must be deleted calling DeleteTrace.
// Note that, if config.TraceInitialState is not empty, this function will
// succeed only if the trace was created and goes into the requested state.
func CreateTrace(config *TraceConfig) (string, error) {
	traceID := randomTraceID()

	var filter *gadgetv1alpha1.ContainerFilter

	// Keep Filter field empty if it is not really used
	if config.CommonFlags.Namespace != "" || config.CommonFlags.Podname != "" ||
		config.CommonFlags.Containername != "" || len(config.CommonFlags.Labels) > 0 {
		filter = &gadgetv1alpha1.ContainerFilter{
			Namespace:     config.CommonFlags.Namespace,
			Podname:       config.CommonFlags.Podname,
			ContainerName: config.CommonFlags.Containername,
			Labels:        config.CommonFlags.Labels,
		}
	}

	trace := &gadgetv1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: config.GadgetName + "-",
			Namespace:    config.GadgetNamespace,
			Annotations: map[string]string{
				GadgetOperation: string(config.Operation),
			},
			Labels: map[string]string{
				GlobalTraceID: traceID,
				// Add all this information here to be able to find the trace thanks
				// to them when calling getTraceListFromParameters().
				"gadgetName": config.GadgetName,
				"nodeName":   config.CommonFlags.Node,
				// Kubernetes labels cannot contain ',' but can contain '_'
				// Kubernetes names cannot contain either, so no need for more complicated escaping
				"namespace":     strings.ReplaceAll(config.CommonFlags.Namespace, ",", "_"),
				"podName":       config.CommonFlags.Podname,
				"containerName": config.CommonFlags.Containername,
				"outputMode":    string(config.TraceOutputMode),
				// We will not add config.TraceOutput as label because it can contain
				// "/" which is forbidden in labels.
			},
		},
		Spec: gadgetv1alpha1.TraceSpec{
			Node:       config.CommonFlags.Node,
			Gadget:     config.GadgetName,
			Filter:     filter,
			RunMode:    gadgetv1alpha1.RunModeManual,
			OutputMode: config.TraceOutputMode,
			Output:     config.TraceOutput,
			Parameters: config.Parameters,
		},
	}

	for key, value := range config.AdditionalLabels {
		v, ok := trace.Labels[key]
		if ok {
			return "", fmt.Errorf("label %q is already present with value %q", key, v)
		}

		trace.Labels[key] = value
	}

	err := createTraces(config.GadgetNamespace, trace)
	if err != nil {
		return "", err
	}

	if config.TraceInitialState != "" {
		// Once the traces are created, we wait for them to be in
		// config.TraceInitialState state, so they are ready to be used by the user.
		_, err = waitForTraceState(config.GadgetNamespace, traceID, string(config.TraceInitialState))
		if err != nil {
			deleteError := DeleteTrace(config.GadgetNamespace, traceID)

			if deleteError != nil {
				fmt.Fprintf(os.Stderr, "Error: deleting trace: %s\n", err)
			}

			return "", err
		}
	}

	return traceID, nil
}

// GetTraceListFromOptions returns a list of traces corresponding to the given
// options.
func GetTraceListFromOptions(gadgetNamespace string, listTracesOptions metav1.ListOptions) (*gadgetv1alpha1.TraceList, error) {
	traceClient, err := getTraceClient()
	if err != nil {
		return nil, err
	}

	return traceClient.GadgetV1alpha1().Traces(gadgetNamespace).List(
		context.TODO(), listTracesOptions,
	)
}

// getTraceListFromID returns an array of pointers to gadgetv1alpha1.Trace
// corresponding to the given traceID.
// If no trace corresponds to this ID, error is set.
func getTraceListFromID(gadgetNamespace string, traceID string) (*gadgetv1alpha1.TraceList, error) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", GlobalTraceID, traceID),
	}

	traces, err := GetTraceListFromOptions(gadgetNamespace, listTracesOptions)
	if err != nil {
		return traces, fmt.Errorf("getting traces from traceID %q: %w", traceID, err)
	}

	if len(traces.Items) == 0 {
		return traces, fmt.Errorf("no traces found for traceID %q", traceID)
	}

	return traces, nil
}

// SetTraceOperation sets the operation of an existing trace.
// If trace does not exist an error is returned.
func SetTraceOperation(gadgetNamespace string, traceID string, operation string) error {
	// We have to wait for the previous operation to start before changing the
	// trace operation.
	// The trace controller deletes the GADGET_OPERATION field from Annotations
	// when it is about to deal with an operation.
	// Thus, to avoid losing operations, we need to wait for GADGET_OPERATION to
	// be deleted before changing to the current operation.
	// It is the same like when you are in the restaurant, you need to wait for
	// the chef to cook the main dishes before ordering the dessert.
	traces, err := waitForNoOperation(gadgetNamespace, traceID)
	if err != nil {
		return err
	}

	for _, trace := range traces.Items {
		localError := updateTraceOperation(gadgetNamespace, &trace, operation)
		if localError != nil {
			err = fmt.Errorf("%w\nError updating trace operation for %q: %w", err, traceID, localError)
		}
	}

	return err
}

// getTraceListerWatcher returns a ListerWatcher on trace(s) for the
// received ID.
// If resourceVersion is set, the watcher will watch for traces which have at
// least the received ResourceVersion, otherwise it will watch all traces.
// This watcher can then be used to wait until the State.Output is modified.
func getTraceListerWatcher(gadgetNamespace, traceID, resourceVersion string) (*cache.ListWatch, error) {
	traceClient, err := getTraceClient()
	if err != nil {
		return nil, err
	}

	traceInterface := traceClient.GadgetV1alpha1().Traces(gadgetNamespace)
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = fmt.Sprintf("%s=%s", GlobalTraceID, traceID)
			options.ResourceVersion = resourceVersion

			return traceInterface.List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = fmt.Sprintf("%s=%s", GlobalTraceID, traceID)
			options.ResourceVersion = resourceVersion

			return traceInterface.Watch(context.TODO(), options)
		},
	}

	return lw, nil
}

// waitForCondition waits for the traces with the ID received as parameter to
// satisfy the conditionFunction received as parameter.
func waitForCondition(gadgetNamespace string, traceID string, conditionFunction func(*gadgetv1alpha1.Trace) bool) (*gadgetv1alpha1.TraceList, error) {
	satisfiedTraces := make(map[string]*gadgetv1alpha1.Trace)
	erroredTraces := make(map[string]*gadgetv1alpha1.Trace)
	var returnedTraces gadgetv1alpha1.TraceList
	nodeWarnings := make(map[string]string)
	nodeErrors := make(map[string]string)

	traceList, err := getTraceListFromID(gadgetNamespace, traceID)
	if err != nil {
		return nil, err
	}

	// Maybe some traces already satisfy conditionFunction?
	for i, trace := range traceList.Items {
		if trace.Status.OperationWarning != "" {
			// The trace can have a warning but satisfies conditionFunction.
			// So, we do not add it to the map here.
			nodeWarnings[trace.Spec.Node] = trace.Status.OperationWarning
		}

		if trace.Status.OperationError != "" {
			erroredTraces[trace.Name] = &traceList.Items[i]

			continue
		}

		if !conditionFunction(&trace) {
			continue
		}

		satisfiedTraces[trace.Name] = &traceList.Items[i]
	}

	tracesNumber := len(traceList.Items)

	// We only watch the traces if there are some which did not already satisfy
	// the conditionFunction.
	if len(satisfiedTraces)+len(erroredTraces) < tracesNumber {
		var traceListerWatcher *cache.ListWatch

		// We will need to list and watch events on them.
		// For this, we will get a ListerWatcher on all the traces which share the
		// same ID.
		// NOTE all the traces on different nodes but linked to one gadget share
		// the same ID.
		// We will also begin to monitor events since the above GET of the traces
		// list thanks to resource version.
		traceListerWatcher, err = getTraceListerWatcher(gadgetNamespace, traceID, traceList.ResourceVersion)
		if err != nil {
			return nil, err
		}

		ctx, cancel := watchtools.ContextWithOptionalTimeout(context.Background(), TraceTimeout)
		defer cancel()

		createdTraces := 0
		_, err = watchtools.UntilWithSync(ctx, traceListerWatcher, &gadgetv1alpha1.Trace{}, nil, func(event watch.Event) (bool, error) {
			// This function will be executed until:
			// 1. The number of watched traces equals the number of traces to watch,
			// i.e. we dealt with the traces which interest us.
			// 2. Or it returns an error.
			// 3. Or time out is fired.
			// NOTE In case 2 and 3, it exists, at least, one trace we did not deal
			// with.
			switch event.Type {
			case watch.Deleted:
				// If for some strange reasons (e.g. users deleted a trace during this
				// operation) a trace is deleted, we need to take care of this by
				// decrementing the tracesNumber.
				// Otherwise we would still wait for the old number and we would
				// timeout.
				tracesNumber--

				trace, _ := event.Object.(*gadgetv1alpha1.Trace)
				traceName := trace.Name

				// We also remove it from the maps to avoid returning a deleted trace
				// and timing out.
				delete(satisfiedTraces, traceName)
				delete(erroredTraces, traceName)

				return false, nil
			case watch.Modified:
				// We will deal with this type of event below
			case watch.Error:
				// Deal particularly with error.
				return false, fmt.Errorf("received event is an error one: %v", event)
			case watch.Added:
				createdTraces++

				// While watching, we will receive watch.Added event for the traces
				// previously created.
				// So, if there are more events than already created traces, it means
				// something wrong happens (e.g. the user creates a trace by snooping on
				// the traceID of existing traces).
				if createdTraces > tracesNumber {
					return false, fmt.Errorf("there must be %d trace(s) and %d were created",
						tracesNumber, createdTraces)
				}
			default:
				// We are not interested in other event types.
				return false, nil
			}

			trace, _ := event.Object.(*gadgetv1alpha1.Trace)

			if trace.Status.OperationWarning != "" {
				// The trace can have a warning but satisfies conditionFunction.
				// So, we do not add it to the map here.
				nodeWarnings[trace.Spec.Node] = trace.Status.OperationWarning
			}

			if trace.Status.OperationError != "" {
				erroredTraces[trace.Name] = trace

				// If the trace satisfied the function, we do not care now because it
				// has an error.
				delete(satisfiedTraces, trace.Name)

				return len(satisfiedTraces)+len(erroredTraces) == tracesNumber, nil
			}

			// If the trace does not satisfy the condition function, we are not
			// interested.
			if !conditionFunction(trace) {
				return false, nil
			}

			satisfiedTraces[trace.Name] = trace

			return len(satisfiedTraces)+len(erroredTraces) == tracesNumber, nil
		})
	}

	for _, trace := range erroredTraces {
		nodeErrors[trace.Spec.Node] = trace.Status.OperationError
	}

	// We print errors whatever happened.
	printTraceFeedback("Error", nodeErrors, tracesNumber)

	// We print warnings only if all trace failed.
	if len(satisfiedTraces) == 0 {
		printTraceFeedback("Warn", nodeWarnings, tracesNumber)
	}

	if err != nil {
		if !wait.Interrupted(err) {
			return nil, err
		}

		// If there is not at least one satisfied trace, return the error.
		if len(satisfiedTraces) == 0 {
			return nil, err
		}

		// Print a message for traces that timed out
		for _, trace := range traceList.Items {
			_, satisfied := satisfiedTraces[trace.Name]
			_, errored := erroredTraces[trace.Name]
			if !satisfied && !errored {
				fmt.Fprintf(os.Stderr,
					"Error: timeout waiting for condition on node %q\n",
					trace.Spec.Node)
			}
		}
	}

	for _, trace := range satisfiedTraces {
		returnedTraces.Items = append(returnedTraces.Items, *trace)
	}

	return &returnedTraces, nil
}

// waitForTraceState waits for the traces with the ID received as parameter to
// be in the expected state.
func waitForTraceState(gadgetNamespace string, traceID string, expectedState string) (*gadgetv1alpha1.TraceList, error) {
	return waitForCondition(gadgetNamespace, traceID, func(trace *gadgetv1alpha1.Trace) bool {
		return trace.Status.State == gadgetv1alpha1.TraceState(expectedState)
	})
}

// waitForNoOperation waits for the traces with the ID received as parameter to
// not have an operation.
func waitForNoOperation(gadgetNamespace string, traceID string) (*gadgetv1alpha1.TraceList, error) {
	return waitForCondition(gadgetNamespace, traceID, func(trace *gadgetv1alpha1.Trace) bool {
		if trace.Annotations == nil {
			return true
		}

		_, present := trace.Annotations[GadgetOperation]
		return !present
	})
}

var sigIntReceivedNumber = 0

// SigHandler installs a handler for all signals which cause termination as
// their default behavior.
// On reception of this signal, the given trace will be deleted.
// This function fixes trace not being deleted when calling:
// kubectl gadget process-collector -A | head -n0
func SigHandler(gadgetNamespace string, traceID *string, printTerminationMessage bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGABRT, syscall.SIGFPE, syscall.SIGSEGV, syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTERM, syscall.SIGBUS, syscall.SIGTRAP)
	go func() {
		sig := <-c

		// This code is here in case DeleteTrace() hangs.
		// In this case, we install again this handler and if SIGINT is received
		// another time (thus getting it twice) we exit the whole program without
		// trying to delete the trace.
		if sig == syscall.SIGINT {
			sigIntReceivedNumber++

			if sigIntReceivedNumber > 1 {
				os.Exit(1)
			}

			SigHandler(gadgetNamespace, traceID, printTerminationMessage)
		}

		if *traceID != "" {
			DeleteTrace(gadgetNamespace, *traceID)
		}
		if sig == syscall.SIGINT {
			if printTerminationMessage {
				fmt.Println("\nTerminating...")
			}
			os.Exit(0)
		} else {
			os.Exit(1)
		}
	}()
}

// PrintTraceOutputFromStream is used to print trace output using generic
// printing function.
// This function is must be used by trace which has TraceOutputMode set to
// Stream.
func PrintTraceOutputFromStream(gadgetNamespace string, traceID string, expectedState string, params *CommonFlags,
	transformLine func(string) string,
) error {
	traces, err := waitForTraceState(gadgetNamespace, traceID, expectedState)
	if err != nil {
		return err
	}

	return genericStreams(gadgetNamespace, params, traces, nil, transformLine)
}

// PrintTraceOutputFromStatus is used to print trace output using function
// pointer provided by caller.
// It will parse trace.Spec.Output and print it calling the function pointer.
func PrintTraceOutputFromStatus(
	gadgetNamespace string,
	traceID string,
	expectedState string,
	customResultsDisplay func(traceOutputMode string, results []string) error,
) error {
	traces, err := waitForTraceState(gadgetNamespace, traceID, expectedState)
	if err != nil {
		return err
	}

	results := make([]string, len(traces.Items))
	traceOutputMode := string(gadgetv1alpha1.TraceOutputModeStatus)
	for i, trace := range traces.Items {
		results[i] = trace.Status.Output
		traceOutputMode = string(trace.Spec.OutputMode)
	}

	// When some multi-round gadgets, like the advise-seccomp, call this
	// function, they don't know the TraceOutputMode used when the gadget was
	// started. Therefore, they need such information together with the output.
	return customResultsDisplay(traceOutputMode, results)
}

// DeleteTrace deletes the traces for the given trace ID using RESTClient.
func DeleteTrace(gadgetNamespace string, traceID string) error {
	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	deleteTraces(gadgetNamespace, traceClient, traceID)

	return nil
}

// labelsFromFilter creates a string containing labels value from the given
// labelFilter.
func labelsFromFilter(filter map[string]string) string {
	labels := ""
	separator := ""

	// Loop on all fields of labelFilter.
	for labelName, labelValue := range filter {
		// If this field has no value, just skip it.
		if labelValue == "" {
			continue
		}

		// Concatenate the label to existing one.
		labels = fmt.Sprintf("%s%s%s=%v", labels, separator, labelName, labelValue)
		separator = ","
	}

	return labels
}

// getTraceListFromParameters returns traces associated with the given config.
func getTraceListFromParameters(config *TraceConfig) ([]gadgetv1alpha1.Trace, error) {
	filter := map[string]string{
		"gadgetName":    config.GadgetName,
		"nodeName":      config.CommonFlags.Node,
		"namespace":     strings.ReplaceAll(config.CommonFlags.Namespace, ",", "_"),
		"podName":       config.CommonFlags.Podname,
		"containerName": config.CommonFlags.Containername,
		"outputMode":    string(config.TraceOutputMode),
	}

	listTracesOptions := metav1.ListOptions{
		LabelSelector: labelsFromFilter(filter),
	}

	traces, err := GetTraceListFromOptions(config.GadgetNamespace, listTracesOptions)
	if err != nil {
		return []gadgetv1alpha1.Trace{}, err
	}

	return traces.Items, nil
}

// PrintAllTraces prints all traces corresponding to the given config.CommonFlags.
func PrintAllTraces(config *TraceConfig) error {
	traces, err := getTraceListFromParameters(config)
	if err != nil {
		return err
	}

	type printingInformation struct {
		namespace     string
		nodes         []string
		podname       string
		containerName string
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

	fmt.Fprintln(w, "NAMESPACE\tNODE(S)\tPOD\tCONTAINER\tTRACEID")

	printingMap := map[string]*printingInformation{}

	for _, trace := range traces {
		id, present := trace.Labels[GlobalTraceID]
		if !present {
			continue
		}

		node := trace.Spec.Node

		_, present = printingMap[id]
		if present {
			if node == "" {
				continue
			}

			// If an entry with this traceID already exists, we just update the node
			// name by concatenating it to the string.
			printingMap[id].nodes = append(printingMap[id].nodes, node)
		} else {
			// Otherwise, we simply create a new entry.
			if filter := trace.Spec.Filter; filter != nil {
				printingMap[id] = &printingInformation{
					namespace:     filter.Namespace,
					nodes:         []string{node},
					podname:       filter.Podname,
					containerName: filter.ContainerName,
				}
			} else {
				printingMap[id] = &printingInformation{
					nodes: []string{node},
				}
			}
		}
	}

	for id, info := range printingMap {
		sort.Strings(info.nodes)
		fmt.Fprintf(w, "%v\t%v\t%v\t%v\t%v\n", info.namespace, strings.Join(info.nodes, ","), info.podname, info.containerName, id)
	}

	w.Flush()

	return nil
}

// RunTraceAndPrintStream creates a trace, prints its output and deletes
// it.
// It equals calling separately CreateTrace(), then PrintTraceOutputFromStream()
// and DeleteTrace().
// This function is thought to be used with "one-run" gadget, i.e. gadget
// which runs a trace when it is created.
func RunTraceAndPrintStream(config *TraceConfig, transformLine func(string) string) error {
	var traceID string

	SigHandler(config.GadgetNamespace, &traceID, config.CommonFlags.OutputMode != commonutils.OutputModeJSON)

	if config.TraceOutputMode != gadgetv1alpha1.TraceOutputModeStream {
		return errors.New("TraceOutputMode must be Stream. Otherwise, call RunTraceAndPrintStatusOutput")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("creating trace: %w", err)
	}

	defer DeleteTrace(config.GadgetNamespace, traceID)

	return PrintTraceOutputFromStream(config.GadgetNamespace, traceID, string(config.TraceOutputState), config.CommonFlags, transformLine)
}

// RunTraceStreamCallback creates a stream trace and calls callback each
// time one of the tracers produces a new line on any of the nodes.
func RunTraceStreamCallback(gadgetNamespace string, config *TraceConfig, callback func(line string, node string)) error {
	var traceID string

	SigHandler(config.GadgetNamespace, &traceID, false)

	if config.TraceOutputMode != gadgetv1alpha1.TraceOutputModeStream {
		return errors.New("TraceOutputMode must be Stream")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("creating trace: %w", err)
	}

	defer DeleteTrace(config.GadgetNamespace, traceID)

	traces, err := waitForTraceState(config.GadgetNamespace, traceID, string(config.TraceOutputState))
	if err != nil {
		return err
	}

	return genericStreams(config.GadgetNamespace, config.CommonFlags, traces, callback, nil)
}

// RunTraceAndPrintStatusOutput creates a trace, prints its output and deletes
// it.
// It equals calling separately CreateTrace(), then PrintTraceOutputFromStatus()
// and DeleteTrace().
// This function is thought to be used with "one-run" gadget, i.e. gadget
// which runs a trace when it is created.
func RunTraceAndPrintStatusOutput(
	config *TraceConfig,
	customResultsDisplay func(traceOutputMode string, results []string) error,
) error {
	var traceID string

	SigHandler(config.GadgetNamespace, &traceID, false)

	if config.TraceOutputMode == gadgetv1alpha1.TraceOutputModeStream {
		return errors.New("TraceOutputMode must not be Stream. Otherwise, call RunTraceAndPrintStream")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("creating trace: %w", err)
	}

	defer DeleteTrace(config.GadgetNamespace, traceID)

	return PrintTraceOutputFromStatus(config.GadgetNamespace, traceID, string(config.TraceOutputState), customResultsDisplay)
}

func genericStreams(
	gadgetNamespace string,
	params *CommonFlags,
	results *gadgetv1alpha1.TraceList,
	callback func(line string, node string),
	transform func(line string) string,
) error {
	completion := make(chan string)

	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		return commonutils.WrapInErrSetupK8sClient(err)
	}

	verbose := params.Verbose && params.OutputMode != commonutils.OutputModeJSON
	// verbose only when not json is used

	config := &PostProcessConfig{
		Flows:     len(results.Items),
		OutStream: os.Stdout,
		ErrStream: os.Stderr,
		Callback:  callback,
		Transform: transform,
		Verbose:   verbose,
	}

	postProcess := NewPostProcess(config)

	streamCount := int32(0)
	for index, i := range results.Items {
		if params.Node != "" && i.Spec.Node != params.Node {
			continue
		}
		atomic.AddInt32(&streamCount, 1)
		go func(nodeName, namespace, name string, index int) {
			cmd := fmt.Sprintf("/bin/gadgettracermanager -call receive-stream -tracerid trace_%s_%s",
				namespace, name)
			postProcess.OutStreams[index].Node = nodeName
			err := ExecPod(client, nodeName, gadgetNamespace, cmd,
				postProcess.OutStreams[index], postProcess.ErrStreams[index])
			if err == nil {
				completion <- fmt.Sprintf("Trace completed on node %q", nodeName)
			} else {
				completion <- fmt.Sprintf("Error: failed to receive stream on node %q: %v", nodeName, err)
			}
		}(i.Spec.Node, i.Namespace, i.Name, index)
	}

	exit := make(chan bool)

	if params.Timeout != 0 {
		go func() {
			time.Sleep(time.Duration(params.Timeout) * time.Second)
			exit <- true
		}()
	}

	for {
		select {
		case msg := <-completion:
			fmt.Fprintln(os.Stderr, msg)
			if atomic.AddInt32(&streamCount, -1) == 0 {
				return nil
			}
		case <-exit:
			return nil
		}
	}
}

// DeleteTracesByGadgetName removes all traces with this gadget name
func DeleteTracesByGadgetName(gadgetNamespace string, gadget string) error {
	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("gadgetName=%s", gadget),
	}

	return traceClient.GadgetV1alpha1().Traces(gadgetNamespace).DeleteCollection(
		context.TODO(), metav1.DeleteOptions{}, listTracesOptions,
	)
}

func ListTracesByGadgetName(gadgetNamespace string, gadget string) ([]gadgetv1alpha1.Trace, error) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("gadgetName=%s", gadget),
	}

	traces, err := GetTraceListFromOptions(gadgetNamespace, listTracesOptions)
	if err != nil {
		return nil, fmt.Errorf("getting traces by gadget name: %w", err)
	}

	return traces.Items, nil
}
