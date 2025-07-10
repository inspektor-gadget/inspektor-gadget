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
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sWait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"

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
		"delete the entire namespace",
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

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return fmt.Errorf("setting up discovery client: %w", err)
	}

	gadgetNamespace := runtimeGlobalParams.Get(grpcruntime.ParamGadgetNamespace).AsString()
	labelSelector := "k8s-app=gadget"
	var errs []string

	// Remove legacy resources
	if err := removeLegacyResources(k8sClient, crdClient); err != nil {
		errs = append(errs, fmt.Sprintf("removing legacy resources: %v", err))
	}

	// Remove all labeled resources
	fmt.Println("Discovering and removing labeled resources...")
	if err := removeAllLabeledResources(dynClient, discoveryClient, gadgetNamespace, labelSelector); err != nil {
		errs = append(errs, fmt.Sprintf("removing labeled resources: %v", err))
	}

	// Handle cleanup wait or namespace deletion
	if err := handleCleanupWait(k8sClient, dynClient, discoveryClient, gadgetNamespace, labelSelector, &errs); err != nil {
		errs = append(errs, err.Error())
	}

	// Remove image policy if present
	imagePolicyName := fmt.Sprintf("%s-image-policy", gadgetNamespace)
	if _, err := dynClient.Resource(clusterImagePolicyResource).Get(context.TODO(), imagePolicyName, metav1.GetOptions{}); err == nil {
		fmt.Println("Removing image policy...")
		if err := dynClient.Resource(clusterImagePolicyResource).Delete(context.TODO(), imagePolicyName, metav1.DeleteOptions{}); err != nil {
			errs = append(errs, fmt.Sprintf("failed removing image policy: %v", err))
		}
	}

	deployinfo.Store(&deployinfo.DeployInfo{})

	if len(errs) > 0 {
		return fmt.Errorf("removing Inspektor Gadget:\n%s", strings.Join(errs, "\n"))
	}

	if undeployWait {
		fmt.Println("Inspektor Gadget successfully removed")
	} else {
		fmt.Println("Inspektor Gadget is being removed")
	}
	return nil
}

// processResourceList discovers and removes resources with the specified label
func processResourceList(dynClient dynamic.Interface, apiResourceLists []*metav1.APIResourceList, namespace, labelSelector string, namespacedOnly bool) {
	listOptions := metav1.ListOptions{LabelSelector: labelSelector}
	ctx := context.TODO()

	for _, apiResourceList := range apiResourceLists {
		if apiResourceList == nil {
			continue
		}

		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			fmt.Printf("Warning: failed to parse group version %s: %v\n", apiResourceList.GroupVersion, err)
			continue
		}

		for _, apiResource := range apiResourceList.APIResources {
			// Filter resources based on scope (namespaced vs cluster-scoped)
			if (namespacedOnly && !apiResource.Namespaced) ||
				(!namespacedOnly && apiResource.Namespaced) {
				continue
			}
			// Skip sub-resources (contain "/") and resources without required capabilities
			if strings.Contains(apiResource.Name, "/") ||
				!slices.Contains(apiResource.Verbs, "list") ||
				!slices.Contains(apiResource.Verbs, "delete") {
				continue
			}

			gvr := schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: apiResource.Name}

			// List resources with the label selector
			var resourceList *unstructured.UnstructuredList
			if namespacedOnly {
				resourceList, err = dynClient.Resource(gvr).Namespace(namespace).List(ctx, listOptions)
			} else {
				resourceList, err = dynClient.Resource(gvr).List(ctx, listOptions)
			}

			if err != nil {
				if errors.IsForbidden(err) || errors.IsNotFound(err) {
					continue
				}
				if namespacedOnly {
					fmt.Printf("Warning: failed to list %s resources: %v\n", gvr.Resource, err)
				}
				continue
			}

			// Delete found resources
			for _, resource := range resourceList.Items {
				resourceName := resource.GetName()
				fmt.Printf("Removing %s: %s\n", apiResource.Kind, resourceName)

				if namespacedOnly {
					err = dynClient.Resource(gvr).Namespace(namespace).Delete(ctx, resourceName, metav1.DeleteOptions{})
				} else {
					err = dynClient.Resource(gvr).Delete(ctx, resourceName, metav1.DeleteOptions{})
				}

				if err != nil && !errors.IsNotFound(err) {
					fmt.Printf("Warning: failed to remove %s %s: %v\n", apiResource.Kind, resourceName, err)
				}
			}
		}
	}
}

// removeResourcesWithLabel discovers and removes all namespaced resources with the specified label
func removeResourcesWithLabel(dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, namespace, labelSelector string) error {
	apiResourceLists, err := discoveryClient.ServerPreferredNamespacedResources()
	if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
		return fmt.Errorf("discovering API resources: %w", err)
	}

	processResourceList(dynClient, apiResourceLists, namespace, labelSelector, true)
	return nil
}

// removeClusterResourcesWithLabel discovers and removes all cluster-scoped resources with the specified label
func removeClusterResourcesWithLabel(dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, labelSelector string) error {
	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
		return fmt.Errorf("discovering cluster API resources: %w", err)
	}

	processResourceList(dynClient, apiResourceLists, "", labelSelector, false)
	return nil
}

func removeAllLabeledResources(dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, namespace, labelSelector string) error {
	if err := removeResourcesWithLabel(dynClient, discoveryClient, namespace, labelSelector); err != nil {
		return fmt.Errorf("namespaced resources: %w", err)
	}
	if err := removeClusterResourcesWithLabel(dynClient, discoveryClient, labelSelector); err != nil {
		return fmt.Errorf("cluster resources: %w", err)
	}
	return nil
}

func removeLegacyResources(k8sClient *kubernetes.Clientset, crdClient *clientset.Clientset) error {
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

	// Even if we're not using CRDs anymore, we keep this code here in case a
	// user tries to undeploy and old IG instance with a newer kubectl-gadget
	// binary.
	fmt.Println("Removing CRD...")
	err := crdClient.ApiextensionsV1().CustomResourceDefinitions().Delete(
		context.TODO(), "traces.gadget.kinvolk.io", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

func handleCleanupWait(k8sClient *kubernetes.Clientset, dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, gadgetNamespace, labelSelector string, errs *[]string) error {
	if deleteNamespace {
		return handleNamespaceDeletion(k8sClient, gadgetNamespace, errs)
	}

	if undeployWait {
		fmt.Println("Waiting for labeled resources to be fully removed...")
		if err := waitForLabeledResourcesDeletion(dynClient, discoveryClient, gadgetNamespace, labelSelector); err != nil {
			return fmt.Errorf("waiting for labeled resources to be removed: %w", err)
		}
	}
	return nil
}

func handleNamespaceDeletion(k8sClient *kubernetes.Clientset, gadgetNamespace string, errs *[]string) error {
	var list *v1.NamespaceList
	var err error

	if undeployWait {
		list, err = k8sClient.CoreV1().Namespaces().List(
			context.TODO(), metav1.ListOptions{
				FieldSelector: "metadata.name=" + gadgetNamespace,
			},
		)
		if err != nil {
			*errs = append(*errs, fmt.Sprintf("listing %q namespace: %s", gadgetNamespace, err))
			return nil
		}

		// nothing to do, namespace doesn't exist
		if list == nil || len(list.Items) == 0 {
			fmt.Printf("Nothing to do, %q namespace doesn't exist\n", gadgetNamespace)
			return nil
		}
	}

	fmt.Println("Removing namespace...")
	err = k8sClient.CoreV1().Namespaces().Delete(
		context.TODO(), gadgetNamespace, metav1.DeleteOptions{},
	)
	if err != nil {
		*errs = append(*errs, fmt.Sprintf("removing namespace: %v", err))
		return nil
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
			*errs = append(*errs, fmt.Sprintf("failed waiting for %q namespace to be removed: %s", gadgetNamespace, err))
		}
	}
	return nil
}

func waitForLabeledResourcesDeletion(dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, namespace, labelSelector string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	listOptions := metav1.ListOptions{LabelSelector: labelSelector}

	return k8sWait.PollUntilContextCancel(ctx, time.Second, true, func(ctx context.Context) (bool, error) {
		apiResourceLists, err := discoveryClient.ServerPreferredNamespacedResources()
		if err != nil && !discovery.IsGroupDiscoveryFailedError(err) {
			return false, err
		}

		// Check all resource types for any remaining resources with the label
		for _, apiResourceList := range apiResourceLists {
			if apiResourceList == nil {
				continue
			}

			gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
			if err != nil {
				continue
			}

			for _, apiResource := range apiResourceList.APIResources {
				if strings.Contains(apiResource.Name, "/") || !slices.Contains(apiResource.Verbs, "list") {
					continue
				}

				gvr := schema.GroupVersionResource{Group: gv.Group, Version: gv.Version, Resource: apiResource.Name}
				resourceList, err := dynClient.Resource(gvr).Namespace(namespace).List(ctx, listOptions)
				if err != nil {
					if errors.IsForbidden(err) || errors.IsNotFound(err) {
						continue
					}
					continue
				}

				if len(resourceList.Items) > 0 {
					return false, nil // Still have resources
				}
			}
		}
		return true, nil // All resources deleted
	})
}
