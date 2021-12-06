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

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/k8sutil"
	"github.com/spf13/cobra"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
)

var undeployCmd = &cobra.Command{
	Use:          "undeploy",
	Short:        "Undeploy Inspektor Gadget from cluster",
	RunE:         runUndeploy,
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(undeployCmd)
}

func runUndeploy(cmd *cobra.Command, args []string) error {
	traceClient, err := utils.GetTraceClient()
	if err != nil {
		return fmt.Errorf("failed to get trace client: %w", err)
	}

	k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return fmt.Errorf("Error setting up Kubernetes client: %w", err)
	}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("Error creating RESTConfig: %w", err)
	}

	crdClient, err := clientset.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("Error setting up CRD client: %w", err)
	}

	errs := []string{}

	// 1. remove traces

	// We need to wait a bit after removing the traces and before
	// removing the daemon set to give the trace controller an
	// opportunity to remove it. If there are still traces after
	// waiting, we patch them removing the finalizers to let Kubernetes
	// remove them.
	// ref https://github.com/kubernetes/kubernetes/issues/60538#issuecomment-369099998
	delay := 10
	i := 0
	n := 7

again:
	err = traceClient.GadgetV1alpha1().Traces("gadget").DeleteCollection(
		context.TODO(), metav1.DeleteOptions{}, metav1.ListOptions{},
	)
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to remove the traces: %s", err))
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)

	traces, err := traceClient.GadgetV1alpha1().Traces("gadget").List(
		context.TODO(), metav1.ListOptions{},
	)
	if err == nil && len(traces.Items) != 0 {
		i++
		if i < n {
			delay = 2 * delay
			goto again
		}

		// It's taking too long to delete the traces. Remove the
		// finalizers and let k8s remove them immediately.
		for _, trace := range traces.Items {
			data := []byte("{\"metadata\":{\"finalizers\":[]}}")
			_, err := traceClient.GadgetV1alpha1().Traces("gadget").Patch(
				context.TODO(), trace.Name, types.MergePatchType, data, metav1.PatchOptions{},
			)
			if err != nil {
				errs = append(
					errs, fmt.Sprintf("failed to patch trace %q: %s", trace.Name, err),
				)
			}
		}
	}

	// 2. remove crd
	err = crdClient.ApiextensionsV1().CustomResourceDefinitions().Delete(
		context.TODO(), "traces.gadget.kinvolk.io", metav1.DeleteOptions{},
	)
	if err != nil {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"traces.gadget.kinvolk.io\" CRD: %s", err),
		)
	}

	// 3. gadget cluster role binding
	err = k8sClient.RbacV1().ClusterRoleBindings().Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget\" cluster role bindings: %s", err),
		)
	}

	// 4. gadget namespace (it also removes daemonset as well as serviceaccount
	// since they live in this namespace).
	err = k8sClient.CoreV1().Namespaces().Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget\" namespace: %s", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("error undeploying IG:\n%s", strings.Join(errs, "\n"))
	}

	return nil
}
