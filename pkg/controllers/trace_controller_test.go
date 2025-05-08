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
	"sync"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	gomegatype "github.com/onsi/gomega/types"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
)

// FakeFactory is a fake implementation of the TraceFactory interface for
// tests. It records the calls to its methods for assertions in the unit tests.
type FakeFactory struct {
	gadgets.BaseFactory
	mu    sync.Mutex
	calls map[string]struct{}
}

func NewFakeFactory() gadgets.TraceFactory {
	return &FakeFactory{
		BaseFactory: gadgets.BaseFactory{DeleteTrace: deleteTrace},
		calls:       make(map[string]struct{}),
	}
}

func deleteTrace(name string, trace interface{}) {
	f := trace.(*FakeFactory)
	f.mu.Lock()
	f.calls["delete/"+name] = struct{}{}
	f.mu.Unlock()
}

func (f *FakeFactory) OutputModesSupported() map[gadgetv1alpha1.TraceOutputMode]struct{} {
	return map[gadgetv1alpha1.TraceOutputMode]struct{}{
		gadgetv1alpha1.TraceOutputModeStatus: {},
	}
}

func (f *FakeFactory) Operations() map[gadgetv1alpha1.Operation]gadgets.TraceOperation {
	n := func() interface{} {
		return f
	}
	return map[gadgetv1alpha1.Operation]gadgets.TraceOperation{
		"magic": {
			Doc: "Collect a snapshot of the list of sockets",
			Operation: func(name string, trace *gadgetv1alpha1.Trace) {
				f.LookupOrCreate(name, n).(*FakeFactory).Magic(trace)
			},
		},
	}
}

func (f *FakeFactory) Magic(trace *gadgetv1alpha1.Trace) {
	f.mu.Lock()
	key := fmt.Sprintf("operation/%s/%s/%s/",
		trace.Namespace,
		trace.Name,
		"magic",
	)
	f.calls[key] = struct{}{}
	f.mu.Unlock()

	trace.Status.OperationError = "FakeError"
	trace.Status.OperationWarning = "FakeWarning"
	trace.Status.State = gadgetv1alpha1.TraceStateCompleted
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

// OperationMethodHasBeenCalled returns a Gomega assertion checking if the
// method Operation() has been called
func OperationMethodHasBeenCalled(factory gadgets.TraceFactory, name, operation string) func() bool {
	fakeGadget := factory.(*FakeFactory)
	key := fmt.Sprintf("operation/%s/%s/",
		name,
		operation,
	)
	return func() bool {
		return fakeGadget.methodHasBeenCalled(key)
	}
}

// DeleteMethodHasBeenCalled returns a Gomega assertion checking if the method
// Delete() has been called
func DeleteMethodHasBeenCalled(factory gadgets.TraceFactory, name string) func() bool {
	fakeGadget := factory.(*FakeFactory)
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
func HaveState(expectedState gadgetv1alpha1.TraceState) gomegatype.GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) gadgetv1alpha1.TraceState {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.State
	}, Equal(expectedState))
}

// HaveOperationError returns a GomegaMatcher that checks if the
// Trace.Status.OperationError has the expected value
func HaveOperationError(expectedOperationError string) gomegatype.GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.OperationError
	}, Equal(expectedOperationError))
}

// HaveOperationWarning returns a GomegaMatcher that checks if the
// Trace.Status.OperationWarning has the expected value
func HaveOperationWarning(expectedOperationWarning string) gomegatype.GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.OperationWarning
	}, Equal(expectedOperationWarning))
}

// HaveOutput returns a GomegaMatcher that checks if the Trace.Status.Output
// has the expected value
func HaveOutput(expectedOutput string) gomegatype.GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		return trace.Status.Output
	}, Equal(expectedOutput))
}

// HaveAnnotation returns a GomegaMatcher that checks if the Trace
// has an annotation with the expected value
func HaveAnnotation(annotation, expectedOperation string) gomegatype.GomegaMatcher {
	return WithTransform(func(trace *gadgetv1alpha1.Trace) string {
		if trace == nil {
			return "<trace is nil>"
		}
		annotations := trace.GetAnnotations()
		if annotations == nil {
			return ""
		}
		op := annotations[annotation]
		return op
	}, Equal(expectedOperation))
}

// Tests

var _ = Context("Controller with a fake gadget", func() {
	ctx := context.TODO()
	traceFactories := make(map[string]gadgets.TraceFactory)
	fakeFactory := NewFakeFactory()
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
						GadgetOperation:  "magic",
						"hiking.walking": "mountains",
					},
				},
				Spec: gadgetv1alpha1.TraceSpec{
					Node:       "fake-node",
					Gadget:     "fakegadget",
					RunMode:    gadgetv1alpha1.RunModeManual,
					OutputMode: gadgetv1alpha1.TraceOutputModeStatus,
				},
			}

			Consistently(UpdatedTrace(ctx, traceObjectKey)).Should(BeNil())

			err := k8sClient.Create(ctx, myTrace)
			Expect(err).NotTo(HaveOccurred(), "failed to create test Trace resource")

			Eventually(OperationMethodHasBeenCalled(fakeFactory, traceObjectKey.String(), "magic")).Should(BeTrue())

			Eventually(UpdatedTrace(ctx, traceObjectKey)).Should(SatisfyAll(
				HaveState(gadgetv1alpha1.TraceStateCompleted),
				HaveOperationError("FakeError"),
				HaveOperationWarning("FakeWarning"),
				HaveOutput("FakeOutput"),
				HaveAnnotation(GadgetOperation, ""),
				HaveAnnotation("hiking.walking", "mountains"),
			))

			Consistently(OperationMethodHasBeenCalled(fakeFactory, traceObjectKey.String(), "magic")).Should(BeFalse())

			err = k8sClient.Delete(ctx, myTrace)
			Expect(err).NotTo(HaveOccurred(), "failed to delete test Trace resource")

			Eventually(DeleteMethodHasBeenCalled(fakeFactory, traceObjectKey.String())).Should(BeTrue())
			Consistently(DeleteMethodHasBeenCalled(fakeFactory, traceObjectKey.String())).Should(BeFalse())
		})
	})
})
