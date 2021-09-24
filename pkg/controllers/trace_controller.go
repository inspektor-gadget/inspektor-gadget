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
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/api/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

const (
	/* Inspired from Gardener
	 * https://gardener.cloud/documentation/guides/administer_shoots/trigger-shoot-operations/
	 */

	GADGET_OPERATION = "gadget.kinvolk.io/operation"
	GADGET_FINALIZER = "gadget.kinvolk.io/finalizer"
)

// TraceReconciler reconciles a Trace object
type TraceReconciler struct {
	Client client.Client
	Scheme *runtime.Scheme
	Node   string

	// TraceFactories contains the trace factories keyed by the gadget name
	TraceFactories map[string]gadgets.TraceFactory
	TracerManager  *gadgettracermanager.GadgetTracerManager
}

//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=traces,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=traces/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=gadget.kinvolk.io,resources=traces/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Trace object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *TraceReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	trace := &gadgetv1alpha1.Trace{}
	err := r.Client.Get(ctx, req.NamespacedName, trace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			log.Infof("Trace %q has been deleted", req.NamespacedName.String())
			return ctrl.Result{}, nil
		}
		log.Errorf("Failed to get Trace: %s", err)
		return ctrl.Result{}, err
	}

	// Each node handles their own traces
	if trace.Spec.Node != r.Node {
		return ctrl.Result{}, nil
	}

	// Lookup factory
	factory, ok := r.TraceFactories[trace.Spec.Gadget]
	if !ok {
		log.Errorf("Unknown gadget %q", trace.Spec.Gadget)
		return ctrl.Result{}, nil
	}

	log.Infof("Reconcile trace %s (gadget %s, node %s)",
		req.NamespacedName,
		trace.Spec.Gadget,
		trace.Spec.Node)

	// If the Trace is under deletion
	if !trace.ObjectMeta.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(trace, GADGET_FINALIZER) {
			// Inform the factory that the trace is being deleted
			factory.Delete(req.NamespacedName.String())

			if r.TracerManager != nil {
				_, err = r.TracerManager.RemoveTracer(ctx,
					&pb.TracerID{Id: gadgets.TraceNameFromNamespacedName(req.NamespacedName)})
				if err != nil {
					// Print error message but don't try again later
					log.Errorf("Failed to delete tracer BPF map: %s", err)
				}
			}

			// Remove our finalizer
			controllerutil.RemoveFinalizer(trace, GADGET_FINALIZER)
			if err := r.Client.Update(ctx, trace); err != nil {
				log.Errorf("Failed to remove finalizer: %s", err)
				return ctrl.Result{}, err
			}
		}
		// Stop reconciliation as the Trace is being deleted
		log.Infof("Let trace %s be deleted", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// The Trace is not being deleted, so register our finalizer
	beforeFinalizer := trace.DeepCopy()
	controllerutil.AddFinalizer(trace, GADGET_FINALIZER)
	if err := r.Client.Patch(ctx, trace, client.MergeFrom(beforeFinalizer)); err != nil {
		log.Errorf("Failed to add finalizer: %s", err)
		return ctrl.Result{}, err
	}

	// Register tracer
	if r.TracerManager != nil {
		_, err = r.TracerManager.AddTracer(ctx,
			&pb.AddTracerRequest{
				Id:       gadgets.TraceNameFromNamespacedName(req.NamespacedName),
				Selector: gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
			})
		if err != nil && !errors.Is(err, os.ErrExist) {
			log.Errorf("Failed to add tracer BPF map: %s", err)
			return ctrl.Result{}, err
		}
	}

	// For now, only support control via the GADGET_OPERATION
	if trace.Spec.RunMode != "Manual" {
		log.Errorf("Unsupported RunMode: %q", trace.Spec.RunMode)
		return ctrl.Result{}, nil
	}

	outputModes := factory.OutputModesSupported()
	if _, ok := outputModes[trace.Spec.OutputMode]; !ok {
		log.Errorf("Unsupported OutputMode: %q", trace.Spec.OutputMode)
		return ctrl.Result{}, nil
	}

	// Lookup annotations
	if trace.ObjectMeta.Annotations == nil {
		log.Info("No annotations. Nothing to do.")
		return ctrl.Result{}, nil
	}
	var op string
	if op, ok = trace.ObjectMeta.Annotations[GADGET_OPERATION]; !ok {
		log.Info("No operation annotation. Nothing to do.")
		return ctrl.Result{}, nil
	}

	params := make(map[string]string)
	for k, v := range trace.ObjectMeta.Annotations {
		if !strings.HasPrefix(k, GADGET_OPERATION+"-") {
			continue
		}
		params[strings.TrimPrefix(k, GADGET_OPERATION+"-")] = v
	}

	log.Infof("Gadget %s operation %q on %s", trace.Spec.Gadget, op, req.NamespacedName)

	// Remove annotations first to avoid another execution in the next
	// reconciliation loop.
	withAnnotation := trace.DeepCopy()
	annotations := trace.GetAnnotations()
	delete(annotations, GADGET_OPERATION)
	for k := range params {
		delete(annotations, GADGET_OPERATION+"-"+k)
	}
	trace.SetAnnotations(annotations)
	err = r.Client.Patch(ctx, trace, client.MergeFrom(withAnnotation))
	if err != nil {
		log.Errorf("Failed to update trace: %s", err)
		return ctrl.Result{}, err
	}

	// Call gadget operation
	traceBeforeOperation := trace.DeepCopy()
	patch := client.MergeFrom(traceBeforeOperation)

	gadgetOperation, ok := factory.Operations()[op]
	if !ok {
		trace.Status.OperationError = fmt.Sprintf("Unknown operation %q", op)
	} else {
		gadgetOperation.Operation(req.NamespacedName.String(), trace)
	}

	if apiequality.Semantic.DeepEqual(traceBeforeOperation.Status, trace.Status) {
		log.Info("Gadget completed operation without changing the trace status")
	} else {
		log.Infof("Gadget completed operation: updating state=%s operationError=%s output=<%d characters>",
			trace.Status.State,
			trace.Status.OperationError,
			len(trace.Status.Output),
		)
		err = r.Client.Status().Patch(ctx, trace, patch)
		if err != nil {
			log.Errorf("Failed to update trace status: %s", err)
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TraceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gadgetv1alpha1.Trace{}).
		Complete(r)
}
