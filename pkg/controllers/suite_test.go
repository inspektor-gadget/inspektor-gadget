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

package controllers

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/envtest/printer"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	gadgetv1alpha1 "github.com/kinvolk/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	//+kubebuilder:scaffold:imports
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

// These tests use Ginkgo (BDD-style Go testing framework). Refer to
// http://onsi.github.io/ginkgo/ to learn more about Ginkgo.

var (
	cfg       *rest.Config
	k8sClient client.Client
	testEnv   *envtest.Environment
)

var controllerTest = flag.Bool("controller-test", false, "run controller tests")

func TestAPIs(t *testing.T) {
	if !*controllerTest {
		t.Skip("skipping controller test.")
	}

	RegisterFailHandler(Fail)

	RunSpecsWithDefaultAndCustomReporters(t,
		"Controller Suite",
		[]Reporter{printer.NewlineReporter{}})
}

var _ = BeforeSuite(func() {
	logf.SetLogger(zap.New(zap.WriteTo(GinkgoWriter), zap.UseDevMode(true)))

	By("bootstrapping test environment")
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join("..", "resources", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
	}

	var err error
	cfg, err = testEnv.Start()
	Expect(err).NotTo(HaveOccurred())
	Expect(cfg).NotTo(BeNil())

	err = gadgetv1alpha1.AddToScheme(clientgoscheme.Scheme)
	Expect(err).NotTo(HaveOccurred())

	//+kubebuilder:scaffold:scheme

	k8sClient, err = client.New(cfg, client.Options{Scheme: clientgoscheme.Scheme})
	Expect(err).NotTo(HaveOccurred())
	Expect(k8sClient).NotTo(BeNil())
}, 60)

var _ = AfterSuite(func() {
	By("tearing down the test environment")
	err := testEnv.Stop()
	Expect(err).NotTo(HaveOccurred())
})

// SetupTest creates a testing environment for the controller with the specific
// gadgets. It creates a temporary test namespace and automatically start and
// stop the TraceReconciler before and after tests.
func SetupTest(ctx context.Context, traceFactories map[string]gadgets.TraceFactory) *core.Namespace {
	var managerCtx context.Context
	var managerCancel context.CancelFunc

	ns := &core.Namespace{}

	BeforeEach(func() {
		managerCtx, managerCancel = context.WithCancel(context.Background())

		*ns = core.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("test-gadget-%d", rand.Intn(1000000)),
			},
		}
		err := k8sClient.Create(ctx, ns)
		Expect(err).NotTo(HaveOccurred(), "failed to create test namespace")

		mgr, err := ctrl.NewManager(cfg, ctrl.Options{})
		Expect(err).NotTo(HaveOccurred(), "failed to create manager")

		// The node does not need to exist. It just needs to match the
		// name in Trace resources.
		node := "fake-node"
		controller := &TraceReconciler{
			Client:         mgr.GetClient(),
			Scheme:         mgr.GetScheme(),
			Node:           node,
			TraceFactories: traceFactories,
			TracerManager:  nil,
		}
		err = controller.SetupWithManager(mgr)
		Expect(err).NotTo(HaveOccurred(), "failed to setup controller")

		go func() {
			err := mgr.Start(managerCtx)
			Expect(err).NotTo(HaveOccurred(), "failed to start manager")
		}()
	})

	AfterEach(func() {
		managerCancel()

		err := k8sClient.Delete(ctx, ns)
		Expect(err).NotTo(HaveOccurred(), "failed to delete test namespace")
	})

	return ns
}
