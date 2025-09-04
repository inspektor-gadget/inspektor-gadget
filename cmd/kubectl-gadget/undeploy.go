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

	"github.com/blang/semver"
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

	// Determine the deployment version to decide on undeploy strategy
	deployedVersion, err := GetDeployedVersion()
	if err != nil {
		return fmt.Errorf("determining deployed version: %w", err)
	}

	// Check if this is a pre-0.43.0 deployment (no labels)
	legacyVersionThreshold, _ := semver.ParseTolerant("0.43.0")
	if deployedVersion.LT(legacyVersionThreshold) && !deployedVersion.EQ(semver.Version{}) {
		fmt.Printf("Detected deployment version v%s (< v0.43.0), using legacy undeploy method...\n", deployedVersion)
		errs := runLegacyUndeploy(k8sClient, crdClient, dynClient, gadgetNamespace)
		return finishUndeploy(errs)
	}

	errs := runLabelBasedUndeploy(k8sClient, crdClient, dynClient, discoveryClient, gadgetNamespace)
	return finishUndeploy(errs)
}

// processResourceList discovers and removes resources with the specified label
func processResourceList(dynClient dynamic.Interface, apiResourceLists []*metav1.APIResourceList, namespace, labelSelector string, namespacedOnly bool) {
	listOptions := metav1.ListOptions{LabelSelector: labelSelector}
	ctx := context.TODO()

	// Check once if endpointslices are available to decide whether to skip endpoints
	endpointSlicesAvailable := hasEndpointSlicesAvailable(apiResourceLists)

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

			// Skip deprecated v1 endpoints if v1 endpointslices are available
			if apiResource.Name == "endpoints" && gv.Group == "" && gv.Version == "v1" && endpointSlicesAvailable {
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

func handleCleanupWait(k8sClient *kubernetes.Clientset, dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, gadgetNamespace, labelSelector string) error {
	if deleteNamespace {
		return handleNamespaceDeletion(k8sClient, gadgetNamespace)
	}

	if undeployWait {
		fmt.Println("Waiting for labeled resources to be fully removed...")
		if err := waitForLabeledResourcesDeletion(dynClient, discoveryClient, gadgetNamespace, labelSelector); err != nil {
			return fmt.Errorf("waiting for labeled resources to be removed: %w", err)
		}
	}
	return nil
}

func handleNamespaceDeletion(k8sClient *kubernetes.Clientset, gadgetNamespace string) error {
	var list *v1.NamespaceList
	var err error

	if undeployWait {
		list, err = k8sClient.CoreV1().Namespaces().List(
			context.TODO(), metav1.ListOptions{
				FieldSelector: "metadata.name=" + gadgetNamespace,
			},
		)
		if err != nil {
			return fmt.Errorf("listing %q namespace: %w", gadgetNamespace, err)
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
		return fmt.Errorf("removing namespace: %w", err)
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
			return fmt.Errorf("waiting for %q namespace to be removed: %w", gadgetNamespace, err)
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

		// Check once if endpointslices are available to decide whether to skip endpoints
		endpointSlicesAvailable := hasEndpointSlicesAvailable(apiResourceLists)

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

				// Skip deprecated v1 endpoints if v1 endpointslices are available
				if apiResource.Name == "endpoints" && gv.Group == "" && gv.Version == "v1" && endpointSlicesAvailable {
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

// runLabelBasedUndeploy implements the new label-based undeploy logic for v0.43.0+
func runLabelBasedUndeploy(k8sClient *kubernetes.Clientset, crdClient *clientset.Clientset, dynClient dynamic.Interface, discoveryClient discovery.DiscoveryInterface, gadgetNamespace string) []string {
	var errs []string
	labelSelector := "k8s-app=gadget"

	// Remove all labeled resources
	fmt.Println("Discovering and removing labeled resources...")
	if err := removeAllLabeledResources(dynClient, discoveryClient, gadgetNamespace, labelSelector); err != nil {
		errs = append(errs, fmt.Sprintf("removing labeled resources: %v", err))
	}

	// Handle cleanup wait or namespace deletion
	if err := handleCleanupWait(k8sClient, dynClient, discoveryClient, gadgetNamespace, labelSelector); err != nil {
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

	return errs
}

// runLegacyUndeploy implements the hardcoded resource removal for versions < 0.43.0
func runLegacyUndeploy(k8sClient *kubernetes.Clientset, crdClient *clientset.Clientset, dynClient dynamic.Interface, gadgetNamespace string) []string {
	var errs []string

	// Remove DaemonSet
	fmt.Println("Removing DaemonSet...")
	err := k8sClient.AppsV1().DaemonSets(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget\" DaemonSet: %s", err))
	}

	// Remove RoleBinding
	fmt.Println("Removing role binding...")
	err = k8sClient.RbacV1().RoleBindings(gadgetNamespace).Delete(
		context.TODO(), "gadget-role-binding", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget-role-binding\" role binding: %s", err))
	}

	// Remove Role
	fmt.Println("Removing role...")
	err = k8sClient.RbacV1().Roles(gadgetNamespace).Delete(
		context.TODO(), "gadget-role", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget-role\" role: %s", err))
	}

	// Remove ClusterRoleBinding
	fmt.Println("Removing cluster role binding...")
	err = k8sClient.RbacV1().ClusterRoleBindings().Delete(
		context.TODO(), "gadget-cluster-role-binding", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget-cluster-role-binding\" cluster role binding: %s", err))
	}

	// Remove ClusterRole
	fmt.Println("Removing cluster role...")
	err = k8sClient.RbacV1().ClusterRoles().Delete(
		context.TODO(), "gadget-cluster-role", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget-cluster-role\" cluster role: %s", err))
	}

	// Remove ConfigMap
	fmt.Println("Removing config map...")
	err = k8sClient.CoreV1().ConfigMaps(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget\" config map: %s", err))
	}

	// Remove ServiceAccount
	fmt.Println("Removing service account...")
	err = k8sClient.CoreV1().ServiceAccounts(gadgetNamespace).Delete(
		context.TODO(), "gadget", metav1.DeleteOptions{},
	)
	if err != nil && !errors.IsNotFound(err) {
		errs = append(errs, fmt.Sprintf("failed to remove \"gadget\" service account: %s", err))
	}

	// Remove image policy if present
	imagePolicyName := fmt.Sprintf("%s-image-policy", gadgetNamespace)
	if _, err := dynClient.Resource(clusterImagePolicyResource).Get(context.TODO(), imagePolicyName, metav1.GetOptions{}); err == nil {
		fmt.Println("Removing image policy...")
		if err := dynClient.Resource(clusterImagePolicyResource).Delete(context.TODO(), imagePolicyName, metav1.DeleteOptions{}); err != nil {
			errs = append(errs, fmt.Sprintf("failed removing image policy: %v", err))
		}
	}

	// Handle namespace deletion or wait for resources
	if err := handleLegacyCleanupWait(k8sClient, gadgetNamespace); err != nil {
		errs = append(errs, err.Error())
	}

	return errs
}

// handleLegacyCleanupWait handles cleanup waiting logic for legacy undeploy
func handleLegacyCleanupWait(k8sClient *kubernetes.Clientset, gadgetNamespace string) error {
	if deleteNamespace {
		return handleNamespaceDeletion(k8sClient, gadgetNamespace)
	}

	if undeployWait {
		fmt.Println("Waiting for DaemonSet to be fully removed...")
		if err := waitForDaemonSetDeletion(k8sClient, gadgetNamespace, "gadget"); err != nil {
			return fmt.Errorf("waiting for DaemonSet to be removed: %w", err)
		}
	}
	return nil
}

// waitForDaemonSetDeletion waits for a DaemonSet to be deleted (for legacy undeploy)
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

// finishUndeploy handles final cleanup and error reporting
func finishUndeploy(errs []string) error {
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

// hasEndpointSlicesAvailable checks if v1 endpointslices are available in the cluster
func hasEndpointSlicesAvailable(apiResourceLists []*metav1.APIResourceList) bool {
	for _, apiResourceList := range apiResourceLists {
		if apiResourceList == nil {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		if gv.Group == "discovery.k8s.io" && gv.Version == "v1" {
			for _, apiResource := range apiResourceList.APIResources {
				if apiResource.Name == "endpointslices" {
					return true
				}
			}
		}
	}
	return false
}
