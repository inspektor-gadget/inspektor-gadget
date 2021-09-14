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

	apimachineryruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	seccompprofilev1alpha1 "sigs.k8s.io/security-profiles-operator/api/seccompprofile/v1alpha1"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	seccomptracer "github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp/tracer"
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
	return `The seccomp gadget traces system calls for each container in order to generate seccomp policies on-demand.`
}

func (f *TraceFactory) OutputModesSupported() map[string]struct{} {
	return map[string]struct{}{
		"Status":           {},
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
			Doc: "Generate a seccomp profile",
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
			r = syscallArrToSeccompPolicy(parts[0], parts[1], b)
		} else {
			r = syscallArrToSeccompPolicy(trace.ObjectMeta.Namespace, trace.Spec.Output, b)
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
		traceSingleton.tracer.Close()
		traceSingleton.tracer = nil
	}

	t.started = false

	trace.Status.OperationError = ""
	trace.Status.State = "Stopped"
	return
}
