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

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sWait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

var undeployCmd = &cobra.Command{
	Use:          "undeploy",
	Short:        "Undeploy Inspektor Gadget from cluster",
	RunE:         runUndeploy,
	SilenceUsage: true,
}

var (
	undeployWait    bool
	deleteNamespace bool
)

const (
	timeout int = 30
)

var clusterImagePolicyResource = schema.GroupVersionResource{
	Group:    "policy.sigstore.dev",
	Version:  "v1beta1",
	Resource: "clusterimagepolicies",
}

func init() {
	rootCmd.AddCommand(undeployCmd)
	undeployCmd.PersistentFlags().BoolVarP(
		&undeployWait,
		"wait", "",
		true,
		"wait for all Inspektor Gadget resources to be deleted before returning",
	)
	undeployCmd.PersistentFlags().BoolVarP(
		&deleteNamespace,
		"delete-namespace", "",
		false,
		"delete the entire namespace (WARNING: this will remove ALL resources in the namespace, not just Inspektor Gadget)",
	)
}

func runUndeploy(cmd *cobra.Command, args []string) error {
	k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return commonutils.WrapInErrSetupK8sClient(err)
	}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("creating RESTConfig: %w", err)
	}

	crdClient, err := clientset.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("setting up CRD client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("setting up dynamic client: %w", err)
	}

	errs := []string{}

	gadgetNamespace := runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).AsString()
	imagePolicyName := fmt.Sprintf("%s-image-policy", gadgetNamespace)

	// 1. Remove DaemonSet
	fmt.Println("Removing DaemonSet...")
	err = k8sClient.AppsV1().DaemonSets(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget\" DaemonSet: %s", err),
		)
	}

	// 2. Remove RoleBinding
	fmt.Println("Removing role binding...")
	err = k8sClient.RbacV1().RoleBindings(gadgetNamespace).Delete(
		context.TODO(), "gadget-role-binding", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget-role-binding\" role binding: %s", err),
		)
	}

	// 3. Remove Role
	fmt.Println("Removing role...")
	err = k8sClient.RbacV1().Roles(gadgetNamespace).Delete(
		context.TODO(), "gadget-role", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget-role\" role: %s", err),
		)
	}

	// 4. Remove ClusterRoleBinding
	fmt.Println("Removing cluster role binding...")
	err = k8sClient.RbacV1().ClusterRoleBindings().Delete(
		context.TODO(), "gadget-cluster-role-binding", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget-cluster-role-binding\" cluster role binding: %s", err),
		)
	}

	// 5. Remove ClusterRole
	fmt.Println("Removing cluster role...")
	err = k8sClient.RbacV1().ClusterRoles().Delete(
		context.TODO(), "gadget-cluster-role", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget-cluster-role\" cluster role: %s", err),
		)
	}

	// 6. Remove ConfigMap
	fmt.Println("Removing config map...")
	err = k8sClient.CoreV1().ConfigMaps(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget\" config map: %s", err),
		)
	}

	// 7. Remove ServiceAccount
	fmt.Println("Removing service account...")
	err = k8sClient.CoreV1().ServiceAccounts(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"gadget\" service account: %s", err),
		)
	}

	// 8. remove crd
	// Even if we're not using CRDs anymore, we keep this code here in case a
	// user tries to undeploy and old IG instance with a newer kubectl-gadget
	// binary.
	fmt.Println("Removing CRD...")
	err = crdClient.ApiextensionsV1().CustomResourceDefinitions().Delete(
		context.TODO(), "traces.gadget.kinvolk.io", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(
			errs, fmt.Sprintf("failed to remove \"traces.gadget.kinvolk.io\" CRD: %s", err),
		)
	}

	// Let's try to remove components of IG versions before v0.5.0,
	// just in case somebody has a newer CLI but is trying to remove
	// an old version of Inspektor Gadget from the cluster. Given
	// that this is a best effort work, we don't track any error.

	// kube-system/gadget daemon set
	k8sClient.AppsV1().DaemonSets("kube-system").Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)

	// gadget cluster role binding
	k8sClient.RbacV1().ClusterRoleBindings().Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)

	// kube-system/gadget service account
	k8sClient.CoreV1().ServiceAccounts("kube-system").Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)

	// 9. delete associated image policy if present
	_, err = dynClient.Resource(clusterImagePolicyResource).Get(context.TODO(), imagePolicyName, metav1.GetOptions{})
	if err == nil {
		fmt.Println("Removing image policy...")
		err = dynClient.Resource(clusterImagePolicyResource).Delete(context.TODO(), imagePolicyName, metav1.DeleteOptions{})
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed removing image policy: %v", err))
		}
	}

	// Note: SeccompProfile resources are not automatically removed as they are
	// user-provided content. Users should manually remove them if needed.

	// 10. gadget namespace (only if deleteNamespace flag is set)
	var list *v1.NamespaceList
	if deleteNamespace {
		if undeployWait {
			list, err = k8sClient.CoreV1().Namespaces().List(
				context.TODO(), metav1.ListOptions{
					FieldSelector: "metadata.name=" + gadgetNamespace,
				},
			)
			if err != nil {
				errs = append(errs, fmt.Sprintf("failed to list %q namespace: %s", gadgetNamespace, err))
				goto out
			}

			// nothing to do, namespace doesn't exist
			if list == nil || len(list.Items) == 0 {
				fmt.Printf("Nothing to do, %q namespace doesn't exist\n", gadgetNamespace)
				goto out
			}
		}

		fmt.Println("Removing namespace...")
		err = k8sClient.CoreV1().Namespaces().Delete(
			context.TODO(), gadgetNamespace, metav1.DeleteOptions{},
		)
		if err != nil {
			errs = append(errs, fmt.Sprintf("failed to remove %q namespace: %s", gadgetNamespace, err))
			goto out
		}

		if undeployWait {
			watcher := cache.NewListWatchFromClient(
				k8sClient.CoreV1().RESTClient(), "namespaces", "", fields.OneTermEqualSelector("metadata.name", gadgetNamespace),
			)

			conditionFunc := func(event watch.Event) (bool, error) {
				switch event.Type {
				case watch.Deleted:
					return true, nil
				case watch.Error:
					return false, fmt.Errorf("watch error: %v", event)
				default:
					return false, nil
				}
			}

			fmt.Println("Waiting for namespace to be removed...")

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer cancel()
			_, err := watchtools.Until(ctx, list.ResourceVersion, watcher, conditionFunc)
			if err != nil {
				errs = append(errs, fmt.Sprintf("failed waiting for %q namespace to be removed: %s", gadgetNamespace, err))
			}
		}
	} else {
		// Wait for DaemonSet to be fully removed if wait flag is set
		if undeployWait {
			fmt.Println("Waiting for DaemonSet to be fully removed...")
			err := waitForDaemonSetDeletion(k8sClient, gadgetNamespace, "gadget")
			if err != nil {
				errs = append(errs, fmt.Sprintf("failed waiting for DaemonSet to be removed: %s", err))
			}
		}
	}

out:
	if len(errs) > 0 {
		return fmt.Errorf("removing Inspektor Gadget:\n%s", strings.Join(errs, "\n"))
	}

	if undeployWait {
		fmt.Println("Inspektor Gadget successfully removed")
	} else {
		fmt.Println("Inspektor Gadget is being removed")
	}

	// Cleanup state related to the deployment
	deployinfo.Store(&deployinfo.DeployInfo{})

	return nil
}

func waitForDaemonSetDeletion(k8sClient *kubernetes.Clientset, namespace, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	return k8sWait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		_, err := k8sClient.AppsV1().DaemonSets(namespace).Get(ctx, name, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, err
		}
		return false, nil
	})
}
