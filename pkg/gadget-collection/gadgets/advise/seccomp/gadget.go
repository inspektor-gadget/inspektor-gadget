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

package seccomp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	seccompprofile "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1beta1"
	k8syaml "sigs.k8s.io/yaml"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	seccomptracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/advise/seccomp/tracer"
)

type Trace struct {
	helpers gadgets.GadgetHelpers
	client  client.Client

	started bool

	// policyGenerated is used to know if there was a policy generated
	// at pod termination so that the Generate() operation does not have
	// to notify that it did not find a pod that matches the filter.
	policyGenerated bool
}

type TraceFactory struct {
	gadgets.BaseFactory
}

type TraceSingleton struct {
	mu     sync.Mutex
	tracer *seccomptracer.Tracer
	users  int
}

var traceSingleton TraceSingleton

func NewFactory() gadgets.TraceFactory {
	return &TraceFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
	}
}

func (f *TraceFactory) Description() string {
	return `The seccomp gadget traces system calls for each container in order to generate
seccomp policies.

The seccomp policies can be generated in two ways:
1. on demand with the gadget.kinvolk.io/operation=generate annotation. In this
   case, the Trace.Spec.Filter should specify the namespace and pod name to the
   exclusion of other fields because there can be only one SeccompProfile
   written in the Trace.Status.Output or in the SeccompProfile resource named
   by Trace.Spec.Output. The on-demand generation supports the outputMode
   Status and ExternalResource.
2. automatically when containers matching the Trace.Spec.Filter terminate. In
   this case, all filters are supported. The at-termination generation supports
   the outputMode ExternalResource and Stream.

The seccomp policies can be written in the Status field of the Trace custom
resource, or in SeccompProfiles custom resources managed by the [Kubernetes
Security Profiles
Operator](https://github.com/kubernetes-sigs/security-profiles-operator).

SeccompProfiles will have the following annotations:

* seccomp.gadget.kinvolk.io/trace: the namespaced name of the Trace custom
  resource that generated this SeccompProfile
* seccomp.gadget.kinvolk.io/node: the node where this SeccompProfile was
  generated
* seccomp.gadget.kinvolk.io/pod: the pod namespaced name of the pod that was
  traced
* seccomp.gadget.kinvolk.io/container: the container name in the pod that was
  traced
* seccomp.gadget.kinvolk.io/ownerReference-APIVersion: the ownerReference's
  APIVersion of the pod that was traced
* seccomp.gadget.kinvolk.io/ownerReference-Kind: the ownerReference's Kind of the
  pod that was traced
* seccomp.gadget.kinvolk.io/ownerReference-Name: the ownerReference's Name of the
  pod that was traced
* seccomp.gadget.kinvolk.io/ownerReference-UID: the ownerReference's UID of the
  pod that was traced

SeccompProfiles will have the same labels as the Trace custom resource that
generated them. They don't have meaning for the seccomp gadget. They are
merely copied for convenience.
`
}

func (f *TraceFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus:           {},
		gadgetv1alpha1.TraceOutputModeStream:           {},
		gadgetv1alpha1.TraceOutputModeExternalResource: {},
	}
}

func (f *TraceFactory) AddToScheme(scheme *apimachineryruntime.Scheme) {
	utilruntime.Must(seccompprofile.AddToScheme(scheme))
}

func deleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		traceSingleton.mu.Lock()
		defer traceSingleton.mu.Unlock()
		traceSingleton.users--
		if traceSingleton.users == 0 {
			trace.helpers.Unsubscribe(genPubSubKey(name))
			traceSingleton.tracer.Close()
			traceSingleton.tracer = nil
		}
	}
}

func (f *TraceFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:  f.Client,
			helpers: f.Helpers,
		}
	}
	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		gadgetv1alpha1.OperationStart: {
			Doc: "Start recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
			Order: 1,
		},
		gadgetv1alpha1.OperationGenerate: {
			Doc: `Generate a seccomp profile for the pod specified in Trace.Spec.Filter. The
namespace and pod name should be specified at the exclusion of other fields.`,
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Generate(trace)
			},
			Order: 2,
		},
		gadgetv1alpha1.OperationStop: {
			Doc: "Stop recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
			Order: 3,
		},
	}
}

type pubSubKey string

func genPubSubKey(name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/seccomp/%s", name))
}

func seccompProfileAddLabelsAndAnnotations(
	r *seccompprofile.SeccompProfile,
	trace *gadgetv1alpha1.Trace,
	podName string,
	containerName string,
	ownerReference *metav1.OwnerReference,
) {
	traceName := fmt.Sprintf("%s/%s", trace.Namespace, trace.Name)
	r.Annotations["seccomp.gadget.kinvolk.io/trace"] = traceName
	r.Annotations["seccomp.gadget.kinvolk.io/node"] = trace.Spec.Node
	r.Annotations["seccomp.gadget.kinvolk.io/pod"] = podName
	r.Annotations["seccomp.gadget.kinvolk.io/container"] = containerName
	if ownerReference != nil {
		r.Annotations["seccomp.gadget.kinvolk.io/ownerReference-APIVersion"] = ownerReference.APIVersion
		r.Annotations["seccomp.gadget.kinvolk.io/ownerReference-Kind"] = ownerReference.Kind
		r.Annotations["seccomp.gadget.kinvolk.io/ownerReference-Name"] = ownerReference.Name
		r.Annotations["seccomp.gadget.kinvolk.io/ownerReference-UID"] = string(ownerReference.UID)
	}

	// Copy labels from the trace into the SeccompProfile. This will allow
	// the CLI to add a label on the trace and gather its output
	if trace.Labels != nil {
		for key, value := range trace.Labels {
			r.Labels[key] = value
		}
	}
}

type SeccompProfileNsName struct {
	namespace string
	name      string

	// generateName indicates whether the name field has to be used as
	// resource's Name or GeneratedName
	generateName bool
}

// getSeccompProfileNextName computes the next profile name that has to be used
// for a specific podname given a SeccompProfile list. This function returns:
// podName: If there do not exist profiles with podname or podname-X as name.
// podName-2: If there exist a profile with the podname but no one with podname-X.
// podName-<X+1>: If there exist at least one profile with podname-X.
func getSeccompProfileNextName(profileList []seccompprofile.SeccompProfile, podName string) string {
	currentCounter := 0
	for _, profile := range profileList {
		if !strings.HasPrefix(profile.Name, podName) {
			continue
		}

		if profile.Name == podName && currentCounter == 0 {
			currentCounter++
			continue
		}

		c, err := strconv.Atoi(strings.TrimLeft(profile.Name, podName+"-"))
		if err != nil {
			// Ignore profiles with "podname" prefix but no "podname-X" syntax.
			continue
		}

		if c > currentCounter {
			currentCounter = c
		}
	}

	// It is the first profile for this pod, use the podname as resource's name.
	if currentCounter == 0 {
		return podName
	}

	return fmt.Sprintf("%s-%d", podName, currentCounter+1)
}

// getSeccompProfileNsName computes the seccomp profile namespace and name
// based on the traceOutputName parameter. If it was not specified or does not
// contains the namespace, fallback to the trace's namespace and podname.
func getSeccompProfileNsName(
	cli client.Client,
	traceNs, traceOutputName, podname string,
) (*SeccompProfileNsName, error) {
	if traceOutputName != "" {
		parts := strings.SplitN(traceOutputName, "/", 2)
		if len(parts) == 2 {
			// Use namespace and prefix-name provided by the user.
			return &SeccompProfileNsName{
				namespace:    parts[0],
				name:         parts[1],
				generateName: true,
			}, nil
		}

		// Fallback to the trace's namespace and use prefix-name provided by the user.
		return &SeccompProfileNsName{
			namespace:    traceNs,
			name:         traceOutputName,
			generateName: true,
		}, nil
	}

	// Fallback to the trace's namespace and podname but adding a counter
	// suffix in case there is already a profile with the podname name.
	profileList := &seccompprofile.SeccompProfileList{}
	err := cli.List(
		context.TODO(),
		profileList,
		client.InNamespace(traceNs),
	)
	if err != nil {
		return nil, fmt.Errorf("retrieving SeccompProfiles in %q: %w", traceNs, err)
	}
	profileName := getSeccompProfileNextName(profileList.Items, podname)

	return &SeccompProfileNsName{
		namespace:    traceNs,
		name:         profileName,
		generateName: false,
	}, nil
}

// generateSeccompPolicy generates a seccomp policy which is ready to be
// created.
func generateSeccompPolicy(client client.Client, trace *gadgetv1alpha1.Trace, syscallNames []string, podname, containername, fullPodName string, ownerReference *metav1.OwnerReference) (*seccompprofile.SeccompProfile, error) {
	profileName, err := getSeccompProfileNsName(
		client,
		trace.Namespace,
		trace.Spec.Output,
		podname,
	)
	if err != nil {
		return nil, fmt.Errorf("getting the profile name: %w", err)
	}

	r := syscallNamesToSeccompPolicy(profileName, syscallNames)
	seccompProfileAddLabelsAndAnnotations(r, trace, fullPodName, containername, ownerReference)

	return r, nil
}

// containerTerminated is a callback called every time a container is
// terminated on the node. It is used to generate a SeccompProfile when a
// container terminates.
func (t *Trace) containerTerminated(trace *gadgetv1alpha1.Trace, event containercollection.PubSubEvent) {
	if traceSingleton.tracer == nil {
		log.Errorf("Seccomp tracer is nil")
		return
	}

	if event.Container.Mntns == 0 {
		log.Errorf("Container has unknown mntns")
		return
	}

	traceName := fmt.Sprintf("%s/%s", trace.Namespace, trace.Name)

	// Get the list of syscallNames from the BPF hash map
	syscallNames, err := traceSingleton.tracer.Peek(event.Container.Mntns)
	if err != nil {
		log.Errorf("peeking syscalls for mntns %d: %s", event.Container.Mntns, err)
		return
	}

	// The container has terminated. Cleanup the BPF hash map
	traceSingleton.tracer.Delete(event.Container.Mntns)

	namespacedName := fmt.Sprintf("%s/%s", event.Container.K8s.Namespace, event.Container.K8s.PodName)

	// This field was fetched when the container was created
	ownerReference := getContainerOwnerReference(event.Container)

	r, err := generateSeccompPolicy(t.client, trace, syscallNames, event.Container.K8s.PodName,
		event.Container.K8s.ContainerName, namespacedName, ownerReference)
	if err != nil {
		log.Errorf("Trace %s: %v", traceName, err)
		return
	}

	switch trace.Spec.OutputMode {
	case gadgetv1alpha1.TraceOutputModeExternalResource:
		log.Infof("Trace %s: creating SeccompProfile for pod %s", traceName, namespacedName)
		err := t.client.Create(context.TODO(), r)
		if err != nil {
			log.Errorf("Failed to create Seccomp Profile for pod %s: %s", namespacedName, err)
			return
		}
		t.policyGenerated = true
	case gadgetv1alpha1.TraceOutputModeStream:
		log.Infof("Trace %s: adding SeccompProfile for pod %s in stream", traceName, namespacedName)
		yamlOutput, err := k8syaml.Marshal(r)
		if err != nil {
			log.Errorf("Failed to convert Seccomp Profile to yaml: %s", err)
			return
		}
		t.helpers.PublishEvent(
			gadgets.TraceName(trace.Namespace, trace.Name),
			fmt.Sprintf("%s\n---\n", string(yamlOutput)),
		)
		t.policyGenerated = true
	}
}

func getContainerOwnerReference(c *containercollection.Container) *metav1.OwnerReference {
	ownerRef, err := c.GetOwnerReference()
	if err != nil {
		log.Warnf("Failed to get owner reference of %s/%s/%s: %s",
			c.K8s.Namespace, c.K8s.PodName, c.K8s.ContainerName, err)
	}
	return ownerRef
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	trace.Status.Output = ""
	if t.started {
		trace.Status.State = gadgetv1alpha1.TraceStateStarted
		t.policyGenerated = false
		return
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()
	if traceSingleton.tracer == nil {
		var err error
		traceSingleton.tracer, err = seccomptracer.NewTracer()
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to start seccomp tracer: %s", err)
			return
		}
	}

	// 'trace' is owned by the controller and could be modified
	// outside of the gadget control. Make a copy for the callback.
	traceCopy := trace.DeepCopy()

	// Subscribe to container creation and termination
	// events. Termination is used to generate a
	// SeccompProfile when a container terminates. Creation
	// is used to fetch the owner reference of the
	// containers to be sure this field is set when the
	// container terminates.
	containers := t.helpers.Subscribe(
		genPubSubKey(trace.Namespace+"/"+trace.Name),
		*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		func(event containercollection.PubSubEvent) {
			switch event.Type {
			case containercollection.EventTypeAddContainer:
				getContainerOwnerReference(event.Container)
			case containercollection.EventTypeRemoveContainer:
				t.containerTerminated(traceCopy, event)
			}
		},
	)

	for _, container := range containers {
		getContainerOwnerReference(container)
	}

	traceSingleton.users++
	t.started = true
	t.policyGenerated = false

	trace.Status.State = gadgetv1alpha1.TraceStateStarted
}

func (t *Trace) Generate(trace *gadgetv1alpha1.Trace) {
	if traceSingleton.tracer == nil {
		log.Errorf("Seccomp tracer is nil")
		return
	}

	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}
	if trace.Spec.Filter == nil || trace.Spec.Filter.Namespace == "" || trace.Spec.Filter.Podname == "" {
		trace.Status.OperationError = "Missing pod"
		return
	}
	if len(trace.Spec.Filter.Labels) != 0 {
		trace.Status.OperationError = "Seccomp gadget does not support filtering by labels"
		return
	}

	var mntns uint64
	var containerName string
	if trace.Spec.Filter.ContainerName != "" {
		mntns = t.helpers.LookupMntnsByContainer(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
			trace.Spec.Filter.ContainerName,
		)
		if mntns == 0 {
			// Notify this only if the policy was not already generated at pod termination
			if !t.policyGenerated {
				trace.Status.OperationWarning = fmt.Sprintf("Container %s/%s/%s not found",
					trace.Spec.Filter.Namespace,
					trace.Spec.Filter.Podname,
					trace.Spec.Filter.ContainerName,
				)
			}
			return
		}
		containerName = trace.Spec.Filter.ContainerName
	} else {
		mntnsMap := t.helpers.LookupMntnsByPod(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
		)
		if len(mntnsMap) == 0 {
			// Notify this only if the policy was not already generated at pod termination
			if !t.policyGenerated {
				trace.Status.OperationWarning = fmt.Sprintf("Pod %s/%s not found",
					trace.Spec.Filter.Namespace,
					trace.Spec.Filter.Podname,
				)
			}
			return
		}

		containerList := []string{}
		for k, v := range mntnsMap {
			containerName = k
			mntns = v
			containerList = append(containerList, k)
		}
		sort.Strings(containerList)

		if len(mntnsMap) > 1 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s has several containers: %v",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
				containerList,
			)
			return
		}
		if mntns == 0 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s has unknown mntns",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
			)
			return
		}
	}

	// Get the list of syscallNames from the BPF hash map
	syscallNames, err := traceSingleton.tracer.Peek(mntns)
	if err != nil {
		trace.Status.OperationError = fmt.Sprintf("peeking syscalls for mntns %d: %s", mntns, err)
		return
	}

	switch trace.Spec.OutputMode {
	case gadgetv1alpha1.TraceOutputModeStatus:
		policy := seccomptracer.SyscallNamesToLinuxSeccomp(syscallNames)
		output, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to marshal seccomp policy: %s", err)
			return
		}

		trace.Status.Output = string(output)
	case gadgetv1alpha1.TraceOutputModeExternalResource:
		podName := fmt.Sprintf("%s/%s", trace.Spec.Filter.Namespace, trace.Spec.Filter.Podname)

		ownerReference := t.helpers.LookupOwnerReferenceByMntns(mntns)

		r, err := generateSeccompPolicy(t.client, trace, syscallNames, trace.Spec.Filter.Podname, containerName, podName, ownerReference)
		if err != nil {
			trace.Status.OperationError = err.Error()
			return
		}

		err = t.client.Create(context.TODO(), r)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to update resource: %s", err)
			return
		}
	case gadgetv1alpha1.TraceOutputModeFile:
		fallthrough
	default:
		trace.Status.OperationError = fmt.Sprintf("OutputMode not supported: %s", trace.Spec.OutputMode)
	}
}

func (t *Trace) Stop(trace *gadgetv1alpha1.Trace) {
	if !t.started {
		trace.Status.OperationError = "Not started"
		return
	}

	traceSingleton.mu.Lock()
	defer traceSingleton.mu.Unlock()

	t.helpers.Unsubscribe(genPubSubKey(trace.Namespace + "/" + trace.Name))

	traceSingleton.users--
	if traceSingleton.users == 0 {
		traceSingleton.tracer.Close()
		traceSingleton.tracer = nil
	}

	t.started = false

	trace.Status.State = gadgetv1alpha1.TraceStateStopped
}
