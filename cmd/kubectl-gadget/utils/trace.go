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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	watchtools "k8s.io/client-go/tools/watch"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	clientset "github.com/kinvolk/inspektor-gadget/pkg/client/clientset/versioned"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
)

const (
	GADGET_OPERATION = "gadget.kinvolk.io/operation"
	// We name it "global" as if one trace is created on several nodes, then each
	// copy of the trace on each node will share the same id.
	GLOBAL_TRACE_ID = "global-trace-id"
	traceTimeout    = 2 * time.Second
)

// TraceConfig is used to contain information used to manage a trace.
type TraceConfig struct {
	// GadgetName is gadget name, e.g. socket-collector.
	GadgetName string

	// Operation is the gadget operation to apply to this trace, e.g. start to
	// start the tracing.
	Operation string

	// TraceOutputMode is the trace output mode, the correct values are:
	// * "Status": The trace prints information when its status changes.
	// * "Stream": The trace prints information as events arrive.
	// * "File": The trace prints information into a file.
	// * "ExternalResource": The trace prints information an external resource,
	// e.g. a seccomp profile.
	TraceOutputMode string

	// TraceOutputState is the state in which the trace can output information.
	// For example, trace for *-collector gadget contains output while in
	// Completed state.
	// But other gadgets, like dns, can contain output only in Started state.
	TraceOutputState string

	// TraceOutput is either the name of the file when TraceOutputMode is File or
	// the name of the external resource when TraceOutputMode is ExternalResource.
	// Otherwise, its value is ignored.
	TraceOutput string

	// TraceInitialState is the state in which the trace should be after its
	// creation.
	// This field is only used by "multi-rounds gadgets" like biolatency.
	TraceInitialState string

	// CommonFlags is used to hold parameters given on the command line interface.
	CommonFlags *CommonFlags

	// Parameters is used to pass specific gadget configurations.
	Parameters map[string]string
}

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

// If there are more than one element in the map and the Error/Warning is
// the same for all the nodes, printTraceFeedback will print it only once.
func printTraceFeedback(m map[string]string, totalNodes int) {
	// Do not print `len(m)` times the same message if it's the same from all nodes
	if len(m) > 1 && len(m) == totalNodes {
		value := getIdenticalValue(m)
		if value != "" {
			fmt.Fprintf(os.Stderr, "Failed to run the gadget on all nodes: %s\n", value)
			return
		}
	}

	for node, msg := range m {
		fmt.Fprintf(os.Stderr, "Failed to run the gadget on node %q: %s\n", node, msg)
	}
}

func deleteTraces(traceClient *clientset.Clientset, traceID string) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", GLOBAL_TRACE_ID, traceID),
	}

	err := traceClient.GadgetV1alpha1().Traces("gadget").DeleteCollection(
		context.TODO(), metav1.DeleteOptions{}, listTracesOptions,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error deleting traces: %q", err)
	}
}

func GetTraceClient() (*clientset.Clientset, error) {
	return getTraceClient()
}

func getTraceClient() (*clientset.Clientset, error) {
	config, err := KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("Error creating RESTConfig: %w", err)
	}

	traceClient, err := clientset.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error setting up trace client: %w", err)
	}

	return traceClient, err
}

// createTraces creates a trace using Kubernetes REST API.
// Note that, this function will create the trace on all existing node if
// trace.Spec.Node is empty.
func createTraces(trace *gadgetv1alpha1.Trace) error {
	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		return fmt.Errorf("Error setting up Kubernetes client: %w", err)
	}

	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("Error listing nodes: %w", err)
	}

	traceNode := trace.Spec.Node
	for _, node := range nodes.Items {
		if traceNode != "" && node.Name != traceNode {
			continue
		}
		// If no particular node was given, we need to apply this trace on all
		// available nodes.
		if traceNode == "" {
			trace.Spec.Node = node.Name
		}

		_, err := traceClient.GadgetV1alpha1().Traces("gadget").Create(
			context.TODO(), trace, metav1.CreateOptions{},
		)
		if err != nil {
			traceID, present := trace.ObjectMeta.Labels[GLOBAL_TRACE_ID]
			if present {
				// Clean before exiting!
				deleteTraces(traceClient, traceID)
			}

			return fmt.Errorf("Error creating trace on node %q: %w", node.Name, err)
		}
	}

	return nil
}

// updateTraceOperation updates operation for an already existing trace using
// Kubernetes REST API.
func updateTraceOperation(trace *gadgetv1alpha1.Trace, operation string) error {
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
				GADGET_OPERATION: operation,
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("Error marshalling the operation annotations: %w", err)
	}

	_, err = traceClient.GadgetV1alpha1().Traces("gadget").Patch(
		context.TODO(), trace.ObjectMeta.Name, types.MergePatchType, patchBytes, metav1.PatchOptions{},
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
			Namespace:    "gadget",
			Annotations: map[string]string{
				GADGET_OPERATION: config.Operation,
			},
			Labels: map[string]string{
				GLOBAL_TRACE_ID: traceID,
				// Add all this information here to be able to find the trace thanks
				// to them when calling getTraceListFromParameters().
				"gadgetName":    config.GadgetName,
				"nodeName":      config.CommonFlags.Node,
				"namespace":     config.CommonFlags.Namespace,
				"podName":       config.CommonFlags.Podname,
				"containerName": config.CommonFlags.Containername,
				"outputMode":    config.TraceOutputMode,
				// We will not add config.TraceOutput as label because it can contain
				// "/" which is forbidden in labels.
			},
		},
		Spec: gadgetv1alpha1.TraceSpec{
			Node:       config.CommonFlags.Node,
			Gadget:     config.GadgetName,
			Filter:     filter,
			RunMode:    "Manual",
			OutputMode: config.TraceOutputMode,
			Output:     config.TraceOutput,
			Parameters: config.Parameters,
		},
	}

	err := createTraces(trace)
	if err != nil {
		return "", err
	}

	if config.TraceInitialState != "" {
		// Once the traces are created, we wait for them to be in
		// config.TraceInitialState state, so they are ready to be used by the user.
		_, err = waitForTraceState(traceID, config.TraceInitialState)
		if err != nil {
			deleteError := DeleteTrace(traceID)

			if deleteError != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}

			return "", err
		}
	}

	return traceID, nil
}

// getTraceListFromOptions returns a list of traces corresponding to the given
// options.
func getTraceListFromOptions(listTracesOptions metav1.ListOptions) (*gadgetv1alpha1.TraceList, error) {
	traceClient, err := getTraceClient()
	if err != nil {
		return nil, err
	}

	return traceClient.GadgetV1alpha1().Traces("gadget").List(
		context.TODO(), listTracesOptions,
	)
}

// getTraceListFromID returns an array of pointers to gadgetv1alpha1.Trace
// corresponding to the given traceID.
// If no trace corresponds to this ID, error is set.
func getTraceListFromID(traceID string) (*gadgetv1alpha1.TraceList, error) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", GLOBAL_TRACE_ID, traceID),
	}

	traces, err := getTraceListFromOptions(listTracesOptions)
	if err != nil {
		return traces, fmt.Errorf("Error getting traces from traceID %q: %w", traceID, err)
	}

	if len(traces.Items) == 0 {
		return traces, fmt.Errorf("No traces found for traceID %q!", traceID)
	}

	return traces, nil
}

// SetTraceOperation sets the operation of an existing trace.
// If trace does not exist an error is returned.
func SetTraceOperation(traceID string, operation string) error {
	traces, err := getTraceListFromID(traceID)
	if err != nil {
		return err
	}

	for _, trace := range traces.Items {
		localError := updateTraceOperation(&trace, operation)
		if localError != nil {
			err = fmt.Errorf("%w\nError updating trace operation for %s: %v", err, traceID, localError)
		}
	}

	return err
}

// untilWithoutRetry is a simplified version (only one function as argument)
// version of UntilWithoutRetry, we keep this here because UntilWithoutRetry
// could be deprecated in the future.
// As archive, here is UntilWithoutRetry documentation:
// UntilWithoutRetry reads items from the watch until each provided condition succeeds, and then returns the last watch
// encountered. The first condition that returns an error terminates the watch (and the event is also returned).
// If no event has been received, the returned event will be nil.
// Conditions are satisfied sequentially so as to provide a useful primitive for higher level composition.
// Waits until context deadline or until context is canceled.
//
// Warning: Unless you have a very specific use case (probably a special Watcher) don't use this function!!!
// Warning: This will fail e.g. on API timeouts and/or 'too old resource version' error.
// Warning: You are most probably looking for a function *Until* or *UntilWithSync* below,
// Warning: solving such issues.
// TODO: Consider making this function private to prevent misuse when the other occurrences in our codebase are gone.
func untilWithoutRetry(ctx context.Context, watcher watch.Interface, condition func(event watch.Event) (bool, error)) (*watch.Event, error) {
	ch := watcher.ResultChan()
	defer watcher.Stop()

	var retEvent *watch.Event

Loop:
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return retEvent, errors.New("watch closed before untilWithoutRetry timeout")
			}
			retEvent = &event

			done, err := condition(event)
			if err != nil {
				return retEvent, err
			}
			if done {
				break Loop
			}

		case <-ctx.Done():
			return retEvent, wait.ErrWaitTimeout
		}
	}

	return retEvent, nil
}

// getTraceWatcher returns a watcher on trace(s) whom ID was given as parameter.
// This watcher can then be used to wait on State.Output modification.
func getTraceWatcher(traceID string) (watch.Interface, error) {
	traceClient, err := getTraceClient()
	if err != nil {
		return nil, err
	}

	watchOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", GLOBAL_TRACE_ID, traceID),
	}

	watcher, err := traceClient.GadgetV1alpha1().Traces("gadget").Watch(context.TODO(), watchOptions)
	if err != nil {
		return nil, err
	}

	return watcher, nil
}

// waitForTraceState wait for traces whom ID is given as parameter to be in the
// expected state.
func waitForTraceState(traceID string, expectedState string) (*gadgetv1alpha1.TraceList, error) {
	var returnedTraces gadgetv1alpha1.TraceList

	tracesNumber := 0
	watchedTracesNumber := 0

	watcher, err := getTraceWatcher(traceID)
	if err != nil {
		return nil, err
	}

	nodeErrors := make(map[string]string)
	nodeWarnings := make(map[string]string)

	ctx, cancel := watchtools.ContextWithOptionalTimeout(context.Background(), traceTimeout)
	_, err = untilWithoutRetry(ctx, watcher, func(event watch.Event) (bool, error) {
		// This function will be executed until:
		// 1. The number of watched traces equals the number of traces, i.e. we
		// dealt with the traces which interest us.
		// 2. Or it returns an error.
		// 3. Or time out is fired.
		// NOTE In case 2 and 3, it exists, at least, one trace we did not deal
		// with.

		// Deal particularly with error.
		if event.Type == watch.Error {
			return false, err
		}

		// We are only interested in Added and Modified event, as we want
		// Status.State value to change.
		// More particularly, we monitor Added event for gadget like dns and
		// Modified for gadget like seccompadvisor.
		if event.Type != watch.Added && event.Type != watch.Modified {
			return false, nil
		}

		if event.Type == watch.Added {
			// The API adds fake watch.Added events, so we use them to count the
			// number of trace:
			// To establish initial state, the watch begins with synthetic "Added"
			// events of all resources instances that exist at the starting resource
			// version
			tracesNumber++
		}

		trace := event.Object.(*gadgetv1alpha1.Trace)

		if trace.Status.OperationWarning != "" {
			watchedTracesNumber++

			nodeWarnings[trace.Spec.Node] = trace.Status.OperationWarning

			return false, nil
		}

		if trace.Status.OperationError != "" {
			watchedTracesNumber++

			nodeErrors[trace.Spec.Node] = trace.Status.OperationError

			return false, nil
		}

		// If the trace is not in the state we expect, we are not interested.
		if trace.Status.State != expectedState {
			return false, nil
		}

		watchedTracesNumber++
		// If the current trace matches our filter we add it to the list of trace
		// we will return.
		returnedTraces.Items = append(returnedTraces.Items, *trace)

		return watchedTracesNumber == tracesNumber, nil
	})
	cancel()

	// We print errors whatever happened.
	defer printTraceFeedback(nodeErrors, tracesNumber)

	// We print warnings only if all trace failed.
	if len(returnedTraces.Items) == 0 {
		printTraceFeedback(nodeWarnings, tracesNumber)
	}

	if err != nil {
		return nil, err
	}

	return &returnedTraces, nil
}

var sigIntReceivedNumber = 0

// sigHandler installs a handler for all signals which cause termination as
// their default behavior.
// On reception of this signal, the given trace will be deleted.
// This function fixes trace not being deleted when calling:
// kubectl gadget process-collector -A | head -n0
func sigHandler(traceID *string) {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL, syscall.SIGABRT, syscall.SIGFPE, syscall.SIGKILL, syscall.SIGSEGV, syscall.SIGPIPE, syscall.SIGALRM, syscall.SIGTERM, syscall.SIGBUS, syscall.SIGTRAP)
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

			sigHandler(traceID)
		}

		if *traceID != "" {
			DeleteTrace(*traceID)
		}
		if sig == syscall.SIGINT {
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
func PrintTraceOutputFromStream(traceID string, expectedState string, params *CommonFlags,
	transformLine func(string) string) error {
	traces, err := waitForTraceState(traceID, expectedState)
	if err != nil {
		return err
	}

	return genericStreamsDisplay(params, traces, transformLine)
}

// PrintTraceOutputFromStatus is used to print trace output using function
// pointer provided by caller.
// It will parse trace.Spec.Output and print it calling the function pointer.
func PrintTraceOutputFromStatus(traceID string, expectedState string, customResultsDisplay func(results []gadgetv1alpha1.Trace) error) error {
	traces, err := waitForTraceState(traceID, expectedState)
	if err != nil {
		return err
	}

	return customResultsDisplay(traces.Items)
}

// DeleteTrace deletes the traces for the given trace ID using RESTClient.
func DeleteTrace(traceID string) error {
	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	deleteTraces(traceClient, traceID)

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
		"namespace":     config.CommonFlags.Namespace,
		"podName":       config.CommonFlags.Podname,
		"containerName": config.CommonFlags.Containername,
		"outputMode":    config.TraceOutputMode,
	}

	listTracesOptions := metav1.ListOptions{
		LabelSelector: labelsFromFilter(filter),
	}

	traces, err := getTraceListFromOptions(listTracesOptions)
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
		id, present := trace.ObjectMeta.Labels[GLOBAL_TRACE_ID]
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

	sigHandler(&traceID)

	if config.TraceOutputMode != "Stream" {
		return errors.New("TraceOutputMode must be Stream. Otherwise, call RunTraceAndPrintStatusOutput!")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("error creating trace: %w", err)
	}

	defer DeleteTrace(traceID)

	return PrintTraceOutputFromStream(traceID, config.TraceOutputState, config.CommonFlags, transformLine)
}

// RunTraceStreamCallback creates a stream trace and calls callback each
// time one of the tracers produces a new line on any of the nodes.
func RunTraceStreamCallback(config *TraceConfig, callback func(line string, node string)) error {
	var traceID string

	sigHandler(&traceID)

	if config.TraceOutputMode != "Stream" {
		return errors.New("TraceOutputMode must be Stream")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("error creating trace: %w", err)
	}

	defer DeleteTrace(traceID)

	traces, err := waitForTraceState(traceID, config.TraceOutputState)
	if err != nil {
		return err
	}

	return genericStreams(config.CommonFlags, traces, callback, nil)
}

// RunTraceAndPrintStatusOutput creates a trace, prints its output and deletes
// it.
// It equals calling separately CreateTrace(), then PrintTraceOutputFromStatus()
// and DeleteTrace().
// This function is thought to be used with "one-run" gadget, i.e. gadget
// which runs a trace when it is created.
func RunTraceAndPrintStatusOutput(config *TraceConfig, customResultsDisplay func(results []gadgetv1alpha1.Trace) error) error {
	var traceID string

	sigHandler(&traceID)

	if config.TraceOutputMode == "Stream" {
		return errors.New("TraceOutputMode must not be Stream. Otherwise, call RunTraceAndPrintStream!")
	}

	traceID, err := CreateTrace(config)
	if err != nil {
		return fmt.Errorf("error creating trace: %w", err)
	}

	defer DeleteTrace(traceID)

	return PrintTraceOutputFromStatus(traceID, config.TraceOutputState, customResultsDisplay)
}

func genericStreamsDisplay(
	params *CommonFlags,
	results *gadgetv1alpha1.TraceList,
	transformLine func(string) string,
) error {
	transform := func(line string) string {
		if params.OutputMode == OutputModeJson {
			return line
		}
		return transformLine(line)
	}

	return genericStreams(params, results, nil, transform)
}

func genericStreams(
	params *CommonFlags,
	results *gadgetv1alpha1.TraceList,
	callback func(line string, node string),
	transform func(line string) string,
) error {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	completion := make(chan string)

	client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
	if err != nil {
		return fmt.Errorf("Error setting up Kubernetes client: %w", err)
	}

	verbose := false
	// verbose only when not json is used
	if params.Verbose && params.OutputMode != OutputModeJson {
		verbose = true
	}

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
			cmd := fmt.Sprintf("exec gadgettracermanager -call receive-stream -tracerid trace_%s_%s",
				namespace, name)
			postProcess.OutStreams[index].Node = nodeName
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
			if params.OutputMode != OutputModeJson {
				fmt.Println("\nTerminating...")
			}
			return nil
		case msg := <-completion:
			fmt.Printf("%s", msg)
			if atomic.AddInt32(&streamCount, -1) == 0 {
				return nil
			}
		}
	}
}

// DeleteTraceByGadgetName removes all traces with this gadget name
func DeleteTracesByGadgetName(gadget string) error {
	traceClient, err := getTraceClient()
	if err != nil {
		return err
	}

	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("gadgetName=%s", gadget),
	}

	return traceClient.GadgetV1alpha1().Traces("gadget").DeleteCollection(
		context.TODO(), metav1.DeleteOptions{}, listTracesOptions,
	)
}

func ListTracesByGadgetName(gadget string) ([]gadgetv1alpha1.Trace, error) {
	listTracesOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("gadgetName=%s", gadget),
	}

	traces, err := getTraceListFromOptions(listTracesOptions)
	if err != nil {
		return nil, fmt.Errorf("Error getting traces by gadget name %w", err)
	}

	return traces.Items, nil
}
