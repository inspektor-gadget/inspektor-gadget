// Copyright 2019-2022 The Inspektor Gadget authors
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

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// TraceTemplateSpec describes the data a Trace should have when created from a template
type TraceTemplateSpec struct {
	// Standard object's metadata of the traces created from this template.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// FIXME: metadata will not be set properly: crd.mk uses controller-gen@v0.4.1 and we need v0.6.0
	// https://github.com/kubernetes-sigs/controller-tools/commit/adfbf775195bf1c2366286684cc77a97b04a8cb9
	// and the option generateEmbeddedObjectMeta=true

	// Specification of the desired behavior of the trace.
	// More info: https://git.k8s.io/community/contributors/devel/sig-architecture/api-conventions.md#spec-and-status
	// +optional
	Spec TraceSpec `json:"spec,omitempty"`
}

// GlobalTraceSpec defines the desired state of GlobalTrace
type GlobalTraceSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// NodeSelector is a selector which must be true for the nodes where
	// the traces are to be deployed
	NodeSelector map[string]string `json:"nodeSelector,omitempty"`

	// Specifies the trace that will be created when creating a GlobalTrace.
	TraceTemplate TraceTemplateSpec `json:"traceTemplate"`
}

// GlobalTraceStatus defines the observed state of GlobalTrace
type GlobalTraceStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// A list of pointers to currently started traces.
	// +optional
	StartedTraces []corev1.ObjectReference `json:"startedTraces,omitempty"`

	// A list of pointers to currently stopped traces.
	// +optional
	StoppedTraces []corev1.ObjectReference `json:"stoppedTraces,omitempty"`

	// A list of pointers to currently completed traces.
	// +optional
	CompletedTraces []corev1.ObjectReference `json:"completedTraces,omitempty"`

	// State is "Started", "Stopped" or "Completed"
	// +kubebuilder:validation:Enum=Started;Stopped;Completed
	State string `json:"state,omitempty"`

	// Output is the output of the gadget
	Output string `json:"output,omitempty"`

	// OperationError is the error returned by the gadget when applying the
	// annotation gadget.kinvolk.io/operation=
	OperationError string `json:"operationError,omitempty"`

	// OperationWarning is returned by the gadget to notify about a malfunction
	// when applying the annotation gadget.kinvolk.io/operation=. Unlike the
	// OperationError that represents a fatal error, the OperationWarning could
	// be ignored according to the context.
	OperationWarning string `json:"operationWarning,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// GlobalTrace is the Schema for the globaltraces API
type GlobalTrace struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   GlobalTraceSpec   `json:"spec,omitempty"`
	Status GlobalTraceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// GlobalTraceList contains a list of GlobalTrace
type GlobalTraceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GlobalTrace `json:"items"`
}

func init() {
	SchemeBuilder.Register(&GlobalTrace{}, &GlobalTraceList{})
}
