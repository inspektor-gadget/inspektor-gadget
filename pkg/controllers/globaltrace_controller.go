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

package controllers

import (
	"context"

	log "github.com/sirupsen/logrus"
	core "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ref "k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

// GlobalTraceReconciler reconciles a GlobalTrace object
type GlobalTraceReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// TraceFactories contains the trace factories keyed by the gadget name
	TraceFactories map[string]gadgets.TraceFactory
}

var traceOwnerKey = ".metadata.ownerReferences.name"

//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=globaltraces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=globaltraces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=globaltraces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the GlobalTrace object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.11.0/pkg/reconcile
func (r *GlobalTraceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	globalTrace := &gadgetv1alpha1.GlobalTrace{}
	err := r.Client.Get(ctx, req.NamespacedName, globalTrace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Infof("GlobalTrace %q has been deleted", req.NamespacedName.String())
			return ctrl.Result{}, nil
		}
		log.Errorf("Failed to get GlobalTrace %q: %s", req.NamespacedName.String(), err)
		return ctrl.Result{}, err
	}

	log.Infof("Reconcile GlobalTrace %s (gadget %s, nodeSelector %s)",
		req.NamespacedName,
		globalTrace.Spec.TraceTemplate.Spec.Gadget,
		globalTrace.Spec.NodeSelector)

	factory, ok := r.TraceFactories[globalTrace.Spec.TraceTemplate.Spec.Gadget]
	if !ok {
		log.Errorf("gadget type not found: %s", globalTrace.Spec.TraceTemplate.Spec.Gadget)
		return ctrl.Result{}, err
	}

	// reconcile Trace objects

	var startedTraces []*gadgetv1alpha1.Trace
	var stoppedTraces []*gadgetv1alpha1.Trace
	var completedTraces []*gadgetv1alpha1.Trace

	var childTraces gadgetv1alpha1.TraceList
	log.Infof("Listing Traces with namespace %q and name %q", req.Namespace, req.Name)
	if err := r.List(ctx, &childTraces, client.InNamespace(req.Namespace), client.MatchingFields{traceOwnerKey: req.Name}); err != nil {
		log.Errorf("unable to list child Traces: %s", err)
		return ctrl.Result{}, err
	}
	traceFromNode := make(map[string]string)
	statusesFromTrace := make(map[string]gadgetv1alpha1.TraceStatus)
	for i, t := range childTraces.Items {
		log.Infof("got child Trace %q with state %q", t.Name, t.Status.State)
		switch t.Status.State {
		case "Started":
			startedTraces = append(startedTraces, &childTraces.Items[i])
		case "Stopped":
			stoppedTraces = append(stoppedTraces, &childTraces.Items[i])
		case "Completed":
			completedTraces = append(completedTraces, &childTraces.Items[i])
		default:
			log.Infof("trace %s has state %q", t.Name, t.Status.State)
		}
		traceFromNode[t.Spec.Node] = t.Name
		statusesFromTrace[t.Name] = t.Status
	}
	log.Infof("Got %+v", traceFromNode)

	getRefs := func(traces []*gadgetv1alpha1.Trace) (out []core.ObjectReference) {
		for _, trace := range traces {
			traceRef, err := ref.GetReference(r.Scheme, trace)
			if err != nil {
				log.Errorf("unable to make reference to trace: %s", err)
				continue
			}
			log.Infof("adding %s", trace.Name)
			out = append(out, *traceRef)
		}
		return out
	}

	globalTraceBefore := globalTrace.DeepCopy()

	globalTrace.Status.StartedTraces = getRefs(startedTraces)
	globalTrace.Status.StoppedTraces = getRefs(stoppedTraces)
	globalTrace.Status.CompletedTraces = getRefs(completedTraces)

	log.Infof("Status %+v", globalTrace.Status)

	globalTrace.Status.Output = factory.MergeStatuses(statusesFromTrace)

	patch := client.MergeFrom(globalTraceBefore)
	if err := r.Status().Patch(ctx, globalTrace, patch); err != nil {
		log.Errorf("unable to patch GlobalTrace status: %s", err)
		return ctrl.Result{}, err
	}

	// Create new traces
	var nodes core.NodeList
	if err := r.List(ctx, &nodes); err != nil {
		log.Error(err, "unable to list nodes")
		return ctrl.Result{}, err
	}

	for _, node := range nodes.Items {
		log.Infof("Node %s", node.Name)
		if _, ok := traceFromNode[node.Name]; !ok {
			err := r.createTraceFromGlobalTrace(ctx, globalTrace, node.Name)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	return ctrl.Result{}, nil
}

func (r *GlobalTraceReconciler) createTraceFromGlobalTrace(ctx context.Context, globalTrace *gadgetv1alpha1.GlobalTrace, nodeName string) error {
	trace := &gadgetv1alpha1.Trace{
		ObjectMeta: metav1.ObjectMeta{
			Labels:       make(map[string]string),
			Annotations:  make(map[string]string),
			GenerateName: globalTrace.Name + "-",
			Namespace:    globalTrace.Namespace,
		},
		Spec: *globalTrace.Spec.TraceTemplate.Spec.DeepCopy(),
	}
	for k, v := range globalTrace.Spec.TraceTemplate.Annotations {
		trace.Annotations[k] = v
	}
	for k, v := range globalTrace.Spec.TraceTemplate.Labels {
		trace.Labels[k] = v
	}
	if err := ctrl.SetControllerReference(globalTrace, trace, r.Scheme); err != nil {
		log.Errorf("unable to set controller reference for trace: %s", err)
		return err
	}
	trace.Spec.Node = nodeName

	if err := r.Create(ctx, trace); err != nil {
		log.Errorf("unable to create Trace for GlobalTrace: %s", err)
		return err
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GlobalTraceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &gadgetv1alpha1.Trace{}, traceOwnerKey, func(rawObj client.Object) []string {
		// grab the trace object, extract the owner...
		trace := rawObj.(*gadgetv1alpha1.Trace)
		owner := metav1.GetControllerOf(trace)
		if owner == nil {
			return nil
		}
		// ...make sure it's a GlobalTrace...
		if owner.APIVersion != gadgetv1alpha1.SchemeGroupVersion.String() || owner.Kind != "GlobalTrace" {
			return nil
		}

		// ...and if so, return it
		return []string{owner.Name}
	}); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&gadgetv1alpha1.GlobalTrace{}).
		Owns(&gadgetv1alpha1.Trace{}).
		Complete(r)
}
