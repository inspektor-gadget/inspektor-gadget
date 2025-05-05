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

	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
)

const (
	/* Inspired from Gardener
	 * https://gardener.cloud/docs/guides/administer_shoots/trigger-shoot-operations/
	 */

	GadgetOperation = "gadget.kinvolk.io/operation"
	GadgetFinalizer = "gadget.kinvolk.io/finalizer"
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

func updateTraceStatus(ctx context.Context, cli client.Client,
	traceNsName string,
	trace *gadgetv1alpha1.Trace,
	patch client.Patch,
) {
	log.Infof("Updating new status of trace %q: "+
		"state=%s operationError=%q operationWarning=%q output=<%d characters>",
		traceNsName,
		trace.Status.State,
		trace.Status.OperationError,
		trace.Status.OperationWarning,
		len(trace.Status.Output),
	)

	err := cli.Status().Patch(ctx, trace, patch)
	if err != nil {
		log.Errorf("Failed to update trace %q status: %s", traceNsName, err)
	}
}

func setTraceOpError(ctx context.Context, cli client.Client,
	traceNsName string,
	trace *gadgetv1alpha1.Trace,
	strError string,
) {
	patch := client.MergeFrom(trace.DeepCopy())
	trace.Status.OperationError = strError
	updateTraceStatus(ctx, cli, traceNsName, trace, patch)
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
			log.Infof("Trace %q has been deleted", req.String())
			return ctrl.Result{}, nil
		}
		log.Errorf("Failed to get Trace %q: %s", req.String(), err)
		return ctrl.Result{}, err
	}

	// Each node handles their own traces
	if trace.Spec.Node != r.Node {
		return ctrl.Result{}, nil
	}

	log.Infof("Reconcile trace %s (gadget %s, node %s)",
		req.NamespacedName,
		trace.Spec.Gadget,
		trace.Spec.Node)

	// Verify if the Trace is under deletion. Notice we must do it before
	// checking the Trace specs to avoid blocking the deletion.
	if !trace.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(trace, GadgetFinalizer) {
			// Inform the factory (if valid gadget) that the trace is being deleted
			factory, ok := r.TraceFactories[trace.Spec.Gadget]
			if ok {
				factory.Delete(req.String())
			}

			if r.TracerManager != nil {
				err = r.TracerManager.RemoveTracer(
					gadgets.TraceNameFromNamespacedName(req.NamespacedName),
				)
				if err != nil {
					// Print error message but don't try again later
					log.Errorf("Failed to delete tracer BPF map: %s", err)
				}
			}

			// Remove our finalizer
			controllerutil.RemoveFinalizer(trace, GadgetFinalizer)
			if err := r.Client.Update(ctx, trace); err != nil {
				log.Errorf("Failed to remove finalizer: %s", err)
				return ctrl.Result{}, err
			}
		}
		// Stop reconciliation as the Trace is being deleted
		log.Infof("Let trace %s be deleted", req.NamespacedName)
		return ctrl.Result{}, nil
	}

	// Check trace specs before adding the finalizer and registering the trace.
	// If there is an error updating the Trace, return anyway nil to prevent
	// the Reconcile() from being called again and again by the controller.
	factory, ok := r.TraceFactories[trace.Spec.Gadget]
	if !ok {
		setTraceOpError(ctx, r.Client, req.String(),
			trace, fmt.Sprintf("Unknown gadget %q", trace.Spec.Gadget))

		return ctrl.Result{}, nil
	}
	if trace.Spec.RunMode != gadgetv1alpha1.RunModeManual {
		setTraceOpError(ctx, r.Client, req.String(),
			trace, fmt.Sprintf("Unsupported RunMode %q for gadget %q",
				trace.Spec.RunMode, trace.Spec.Gadget))

		return ctrl.Result{}, nil
	}
	outputModes := factory.OutputModesSupported()
	if _, ok := outputModes[trace.Spec.OutputMode]; !ok {
		setTraceOpError(ctx, r.Client, req.String(),
			trace, fmt.Sprintf("Unsupported OutputMode %q for gadget %q",
				trace.Spec.OutputMode, trace.Spec.Gadget))

		return ctrl.Result{}, nil
	}

	// The Trace is not being deleted and specs are valid, we can register our finalizer
	beforeFinalizer := trace.DeepCopy()
	controllerutil.AddFinalizer(trace, GadgetFinalizer)
	if err := r.Client.Patch(ctx, trace, client.MergeFrom(beforeFinalizer)); err != nil {
		log.Errorf("Failed to add finalizer: %s", err)
		return ctrl.Result{}, err
	}

	// Register tracer
	if r.TracerManager != nil {
		err = r.TracerManager.AddTracer(
			gadgets.TraceNameFromNamespacedName(req.NamespacedName),
			*gadgets.ContainerSelectorFromContainerFilter(trace.Spec.Filter),
		)
		if err != nil && !errors.Is(err, os.ErrExist) {
			log.Errorf("Failed to add tracer BPF map: %s", err)
			return ctrl.Result{}, err
		}
	}

	// Lookup annotations
	if trace.Annotations == nil {
		log.Info("No annotations. Nothing to do.")
		return ctrl.Result{}, nil
	}

	// For now, only support control via the GADGET_OPERATION
	var op string
	if op, ok = trace.Annotations[GadgetOperation]; !ok {
		log.Info("No operation annotation. Nothing to do.")
		return ctrl.Result{}, nil
	}

	params := make(map[string]string)
	for k, v := range trace.Annotations {
		if !strings.HasPrefix(k, GadgetOperation+"-") {
			continue
		}
		params[strings.TrimPrefix(k, GadgetOperation+"-")] = v
	}

	log.Infof("Gadget %s operation %q on %s", trace.Spec.Gadget, op, req.NamespacedName)

	// Remove annotations first to avoid another execution in the next
	// reconciliation loop.
	withAnnotation := trace.DeepCopy()
	annotations := trace.GetAnnotations()
	delete(annotations, GadgetOperation)
	for k := range params {
		delete(annotations, GadgetOperation+"-"+k)
	}
	trace.SetAnnotations(annotations)
	err = r.Client.Patch(ctx, trace, client.MergeFrom(withAnnotation))
	if err != nil {
		log.Errorf("Failed to update trace: %s", err)
		return ctrl.Result{}, err
	}

	// Check operation is supported for this specific gadget
	gadgetOperation, ok := factory.Operations()[gadgetv1alpha1.Operation(op)]
	if !ok {
		setTraceOpError(ctx, r.Client, req.String(),
			trace, fmt.Sprintf("Unsupported operation %q for gadget %q",
				op, trace.Spec.Gadget))

		return ctrl.Result{}, nil
	}

	// Call gadget operation
	traceBeforeOperation := trace.DeepCopy()
	trace.Status.OperationError = ""
	trace.Status.OperationWarning = ""
	patch := client.MergeFrom(traceBeforeOperation)
	gadgetOperation.Operation(req.String(), trace)

	if apiequality.Semantic.DeepEqual(traceBeforeOperation.Status, trace.Status) {
		log.Info("Gadget completed operation without changing the trace status")
	} else {
		log.Infof("Gadget completed operation. Trace status will be updated accordingly")
		updateTraceStatus(ctx, r.Client, req.String(), trace, patch)
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TraceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gadgetv1alpha1.Trace{}).
		Complete(r)
}
