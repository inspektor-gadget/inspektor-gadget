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
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"
	k8syaml "sigs.k8s.io/yaml"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	seccomptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
)

type Trace struct {
	resolver gadgets.Resolver
	client   client.Client

	started bool
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
	return &TraceFactory{}
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
* seccomp.gadget.kinvolk.io/container-id: the container ID in the pod that
  was traced. Typically, 64 hexadecimal characters.
* seccomp.gadget.kinvolk.io/pid: the process ID of the container in the pod
  that was traced.

SeccompProfiles will have the same labels as the Trace custom resource that
generated them. They don't have meaning for the seccomp gadget. They are
merely copied for convenience.
`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status":           {},
		"Stream":           {},
		"ExternalResource": {},
	}
}

func (f *TraceFactory) AddToScheme(scheme *apimachineryruntime.Scheme) {
	utilruntime.Must(seccompprofilev1alpha1.AddToScheme(scheme))
}

func (f *TraceFactory) DeleteTrace(name string, t interface{}) {
	trace := t.(*Trace)
	if trace.started {
		traceSingleton.mu.Lock()
		defer traceSingleton.mu.Unlock()
		traceSingleton.users--
		if traceSingleton.users == 0 {
			traceSingleton.tracer.Close()
			traceSingleton.tracer = nil
		}
	}
}

func (f *TraceFactory) Operations() map[string]gadgets.TraceOperation {
	n := func() interface{} {
		return &Trace{
			client:   f.Client,
			resolver: f.Resolver,
		}
	}
	return map[string]gadgets.TraceOperation{
		"start": {
			Doc: "Start recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Start(trace)
			},
			Order: 1,
		},
		"generate": {
			Doc: `Generate a seccomp profile for the pod specified in Trace.Spec.Filter. The
namespace and pod name should be specified at the exclusion of other fields.`,
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Generate(trace)
			},
			Order: 2,
		},
		"stop": {
			Doc: "Stop recording syscalls",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*Trace).Stop(trace)
			},
			Order: 3,
		},
	}
}

type pubSubKey string

func genPubSubKey(namespace, name string) pubSubKey {
	return pubSubKey(fmt.Sprintf("gadget/seccomp/%s/%s", namespace, name))
}

// containerTerminated is a callback called every time a container is
// terminated on the node. It is used to generate a SeccompProfile when a
// container terminates.
func (t *Trace) containerTerminated(trace *gadgetv1alpha1.Trace, event pubsub.PubSubEvent) {
	if event.Container.Mntns == 0 {
		log.Errorf("Container has unknown mntns")
		return
	}

	// Get the list of syscalls from the BPF hash map
	b := traceSingleton.tracer.Peek(event.Container.Mntns)

	// The container has terminated. Cleanup the BPF hash map
	traceSingleton.tracer.Delete(event.Container.Mntns)

	var r *seccompprofilev1alpha1.SeccompProfile
	generateName := trace.ObjectMeta.Name + "-"
	r = syscallArrToSeccompPolicy(trace.ObjectMeta.Namespace, "", generateName, b)

	// Copy labels from the trace into the SeccompProfile. This will allow
	// the CLI to add a label on the trace and gather its output
	if trace.ObjectMeta.Labels != nil {
		for key, value := range trace.ObjectMeta.Labels {
			r.ObjectMeta.Labels[key] = value
		}
	}
	podName := fmt.Sprintf("%s/%s", event.Container.Namespace, event.Container.Podname)
	traceName := fmt.Sprintf("%s/%s", trace.ObjectMeta.Namespace, trace.ObjectMeta.Name)
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/trace"] = traceName
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/node"] = trace.Spec.Node
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/pod"] = podName
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/container"] = event.Container.Name
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/container-id"] = event.Container.Id
	r.ObjectMeta.Annotations["seccomp.gadget.kinvolk.io/pid"] = fmt.Sprint(event.Container.Pid)

	switch trace.Spec.OutputMode {
	case "ExternalResource":
		log.Infof("Trace %s: creating SeccompProfile for pod %s", traceName, podName)
		err := t.client.Create(context.TODO(), r)
		if err != nil {
			log.Errorf("Failed to create Seccomp Profile for pod %s: %s", podName, err)
		}
	case "Stream":
		log.Infof("Trace %s: adding SeccompProfile for pod %s in stream", traceName, podName)
		yamlOutput, err := k8syaml.Marshal(r)
		if err != nil {
			log.Errorf("Failed to convert Seccomp Profile to yaml: %s", err)
			return
		}
		t.resolver.PublishEvent(
			gadgets.TraceName(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
			fmt.Sprintf("%s\n---\n", string(yamlOutput)),
		)
	}
}

func (t *Trace) Start(trace *gadgetv1alpha1.Trace) {
	if t.started {
		trace.Status.OperationError = ""
		trace.Status.Output = ""
		trace.Status.State = "Started"
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

		// 'trace' is owned by the controller and could be modified
		// outside of the gadget control. Make a copy for the callback.
		traceCopy := trace.DeepCopy()

		// Subscribes to container termination events in order to
		// generate a SeccompProfile when a container terminates. We
		// don't need the list of existing containers, so the return
		// value is ignored.
		_ = t.resolver.Subscribe(
			genPubSubKey(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name),
			*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
			func(event pubsub.PubSubEvent) {
				// Ignore container creation events.
				if event.Type != pubsub.EVENT_TYPE_REMOVE_CONTAINER {
					return
				}
				t.containerTerminated(traceCopy, event)
			},
		)
	}
	traceSingleton.users++
	t.started = true

	trace.Status.OperationError = ""
	trace.Status.Output = ""
	trace.Status.State = "Started"
	return
}

func (t *Trace) Generate(trace *gadgetv1alpha1.Trace) {
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
	if trace.Spec.Filter.ContainerName != "" {
		mntns = t.resolver.LookupMntnsByContainer(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
			trace.Spec.Filter.ContainerName,
		)
		if mntns == 0 {
			trace.Status.OperationError = fmt.Sprintf("Container %s/%s/%s not found on this node",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
				trace.Spec.Filter.ContainerName,
			)
			return
		}
	} else {
		mntnsMap := t.resolver.LookupMntnsByPod(
			trace.Spec.Filter.Namespace,
			trace.Spec.Filter.Podname,
		)
		if len(mntnsMap) == 0 {
			trace.Status.OperationError = fmt.Sprintf("Pod %s/%s not found on this node",
				trace.Spec.Filter.Namespace,
				trace.Spec.Filter.Podname,
			)
			return
		}

		containerList := []string{}
		for k, v := range mntnsMap {
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

	// Get the list of syscalls from the BPF hash map
	b := traceSingleton.tracer.Peek(mntns)

	switch trace.Spec.OutputMode {
	case "Status":
		policy := syscallArrToLinuxSeccomp(b)
		output, err := json.MarshalIndent(policy, "", "  ")
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to marshal seccomp policy: %s", err)
			return
		}

		trace.Status.Output = string(output)
		trace.Status.OperationError = ""
	case "ExternalResource":
		parts := strings.SplitN(trace.Spec.Output, "/", 2)
		var r *seccompprofilev1alpha1.SeccompProfile
		if len(parts) == 2 {
			r = syscallArrToSeccompPolicy(parts[0], parts[1], "", b)
		} else {
			r = syscallArrToSeccompPolicy(trace.ObjectMeta.Namespace, trace.Spec.Output, "", b)
		}
		err := t.client.Create(context.TODO(), r)
		if err != nil {
			trace.Status.OperationError = fmt.Sprintf("Failed to update resource: %s", err)
			return
		}
		trace.Status.OperationError = ""
	case "File":
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
	traceSingleton.users--
	if traceSingleton.users == 0 {
		t.resolver.Unsubscribe(genPubSubKey(trace.ObjectMeta.Namespace, trace.ObjectMeta.Name))
		traceSingleton.tracer.Close()
		traceSingleton.tracer = nil
	}

	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}
