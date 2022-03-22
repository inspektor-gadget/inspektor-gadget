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

package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"

	gadgetkinvolkiov1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/controllers"
	gadgetcollection "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager"
	//+kubebuilder:scaffold:imports
)

func startController(node string, tracerManager *gadgettracermanager.GadgetTracerManager) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))

	utilruntime.Must(gadgetkinvolkiov1alpha1.AddToScheme(scheme))
	//+kubebuilder:scaffold:scheme

	traceFactories := gadgetcollection.TraceFactories()

	for _, factory := range traceFactories {
		factoryWithScheme, ok := factory.(gadgets.TraceFactoryWithScheme)
		if ok {
			factoryWithScheme.AddToScheme(scheme)
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0", // TCP port can be set to "0" to disable the metrics serving
	})
	if err != nil {
		log.Errorf("unable to start manager: %s", err)
		os.Exit(1)
	}

	for _, factory := range traceFactories {
		factory.Initialize(tracerManager, mgr.GetClient())
	}

	if err = (&controllers.TraceReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		Node:           node,
		TraceFactories: traceFactories,
		TracerManager:  tracerManager,
	}).SetupWithManager(mgr); err != nil {
		log.Errorf("unable to create Trace controller: %s", err)
		os.Exit(1)
	}
	if err = (&controllers.GlobalTraceReconciler{
		Client:         mgr.GetClient(),
		Scheme:         mgr.GetScheme(),
		TraceFactories: traceFactories,
	}).SetupWithManager(mgr); err != nil {
		log.Errorf("unable to create GlobalTrace controller: %s", err)
		os.Exit(1)
	}
	//+kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Errorf("unable to set up health check: %s", err)
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Errorf("unable to set up ready check: %s", err)
		os.Exit(1)
	}

	log.Info("Starting trace controller manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Errorf("problem running manager: %s", err)
		os.Exit(1)
	}
}
