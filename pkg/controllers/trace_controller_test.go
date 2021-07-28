// Copyright 2021 The Inspektor Gadget authors
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

package controllers

import (
	"context"
	"fmt"
	"sort"
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

// FakeFactory is a fake implementation of the TraceFactory interface for
// tests. It records the calls to its methods for assertions in the unit tests.
type FakeFactory struct {
	mu    sync.Mutex
	calls map[string]struct{}
}

func (f *FakeFactory) LookupOrCreate(name types.NamespacedName) gadgets.Trace {
	f.mu.Lock()
	f.calls["lookup/"+name.String()] = struct{}{}
	f.mu.Unlock()
	return f
}

func (f *FakeFactory) Delete(name types.NamespacedName) error {
	f.mu.Lock()
	f.calls["delete/"+name.String()] = struct{}{}
	f.mu.Unlock()
	return nil
}

func (f *FakeFactory) Operation(trace *gadgetv1alpha1.Trace, resolver gadgets.Resolver, operation string, params map[string]string) {
	f.mu.Lock()
	key := fmt.Sprintf("operation/%s/%s/%s/",
		trace.ObjectMeta.Namespace,
		trace.ObjectMeta.Name,
		operation,
	)
	paramsKeys := make([]string, 0, len(params))
	for k := range params {
		paramsKeys = append(paramsKeys, k)
	}
	sort.Strings(paramsKeys)

	for _, k := range paramsKeys {
		key += fmt.Sprintf("%s/%s/", k, params[k])
	}
	f.calls[key] = struct{}{}
	f.mu.Unlock()

	trace.Status.OperationError = "FakeError"
	trace.Status.State = "FakeState"
	trace.Status.Output = "FakeOutput"
}

// methodHasBeenCalled is a helper function to check if a method has been
// called on the gadget
func (f *FakeFactory) methodHasBeenCalled(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.calls[key]
	delete(f.calls, key)
	return ok
}

// LookupOrCreateMethodHasBeenCalled returns a Gomega assertion checking if the method
// LookupOrCreate() has been called
func LookupOrCreateMethodHasBeenCalled(fakeGadget *FakeFactory, name string) func() bool {
	key := "lookup/" + name
	return func() bool {
		return fakeGadget.methodHasBeenCalled(key)
	}
}

// OperationMethodHasBeenCalled returns a Gomega assertion checking if the
// method Operation() has been called
func OperationMethodHasBeenCalled(fakeGadget *FakeFactory, name, operation, params string) func() bool {
	key := fmt.Sprintf("operation/%s/%s/%s",
		name,
		operation,
		params,
	)
	return func() bool {
		return fakeGadget.methodHasBeenCalled(key)
	}
}

// DeleteMethodHasBeenCalled returns a Gomega assertion checking if the method
// Delete() has been called
func DeleteMethodHasBeenCalled(fakeGadget *FakeFactory, name string) func() bool {
	key := "delete/" + name
	return func() bool {
		return fakeGadget.methodHasBeenCalled(key)
	}
}

// UpdatedTrace returns a function that fetches the Trace object in a way that
// can be used in Gomega's 'Eventually' or 'Consistently' methods.
func UpdatedTrace(ctx context.Context, key client.ObjectKey) func() *gadgetv1alpha1.Trace {
	trace := &gadgetv1alpha1.Trace{}

	return func() *gadgetv1alpha1.Trace {
		err := k8sClient.Get(ctx, key, trace)
		if err != nil {
			return nil
		} else {
			return trace
		}
	}
}

// HaveState returns a GomegaMatcher that checks if the Trace.Status.State has
// the expected value
func HaveState(expectedState string) GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.State
	}, Equal(expectedState))
}

// HaveOperationError returns a GomegaMatcher that checks if the
// Trace.Status.OperationError has the expected value
func HaveOperationError(expectedOperationError string) GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.OperationError
	}, Equal(expectedOperationError))
}

// HaveOutput returns a GomegaMatcher that checks if the Trace.Status.Output
// has the expected value
func HaveOutput(expectedOutput string) GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.Output
	}, Equal(expectedOutput))
}

// HaveAnnotation returns a GomegaMatcher that checks if the Trace
// has an annotation with the expected value
func HaveAnnotation(annotation, expectedOperation string) GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		annotations := trace.GetAnnotations()
		if annotations == nil {
			return ""
		}
		op, _ := annotations[annotation]
		return op
	}, Equal(expectedOperation))
}

// Tests

var _ = Context("Controller with a fake gadget", func() {
	ctx := context.TODO()
	traceFactories := make(map[string]gadgets.TraceFactory)
	fakeFactory := &FakeFactory{
		calls: make(map[string]struct{}),
	}
	traceFactories["fakegadget"] = fakeFactory

	ns := SetupTest(ctx, traceFactories)

	Describe("when no existing resources exist", func() {
		It("should create a new Trace resource", func() {
			traceObjectKey := client.ObjectKey{
				Name:      "mytrace",
				Namespace: ns.Name,
			}

			myTrace := &gadgetv1alpha1.Trace{
				ObjectMeta: metav1.ObjectMeta{
					Name:      traceObjectKey.Name,
					Namespace: traceObjectKey.Namespace,
					Annotations: map[string]string{
						GADGET_OPERATION: "magic",
						"hiking.walking": "mountains",
					},
				},
				Spec: gadgetv1alpha1.TraceSpec{
					Node:       "fake-node",
					Gadget:     "fakegadget",
					RunMode:    "Manual",
					OutputMode: "Status",
				},
			}

			Consistently(UpdatedTrace(ctx, traceObjectKey)).Should(BeNil())

			err := k8sClient.Create(ctx, myTrace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test Trace resource")

			Eventually(LookupOrCreateMethodHasBeenCalled(fakeFactory, traceObjectKey.String())).Should(BeTrue())
			Eventually(OperationMethodHasBeenCalled(fakeFactory, traceObjectKey.String(), "magic", "")).Should(BeTrue())

			Eventually(UpdatedTrace(ctx, traceObjectKey)).Should(SatisfyAll(
				HaveState("FakeState"),
				HaveOperationError("FakeError"),
				HaveOutput("FakeOutput"),
				HaveAnnotation(GADGET_OPERATION, ""),
				HaveAnnotation("hiking.walking", "mountains"),
			))

			Consistently(OperationMethodHasBeenCalled(fakeFactory, traceObjectKey.String(), "magic", "")).Should(BeFalse())

			err = k8sClient.Delete(ctx, myTrace)
			Expect(err).NotTo(HaveOccurred(), "failed to delete test Trace resource")

			Eventually(DeleteMethodHasBeenCalled(fakeFactory, traceObjectKey.String())).Should(BeTrue())
			Consistently(DeleteMethodHasBeenCalled(fakeFactory, traceObjectKey.String())).Should(BeFalse())
		})
	})
})
