// Copyright 2019-2023 The Inspektor Gadget authors
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
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/apimachinery/pkg/types"
	k8sversion "k8s.io/apimachinery/pkg/util/version"
	utilwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/cache"
	watchtools "k8s.io/client-go/tools/watch"
	"sigs.k8s.io/yaml"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

var deployCmd = &cobra.Command{
	Use:          "deploy",
	Short:        "Deploy Inspektor Gadget on the cluster",
	SilenceUsage: true,
	RunE:         runDeploy,
}

// This is set during build.
var gadgetimage = "undefined"

var (
	image               string
	imagePullPolicy     string
	hookMode            string
	livenessProbe       bool
	deployTimeout       time.Duration
	fallbackPodInformer bool
	printOnly           bool
	quiet               bool
	debug               bool
	wait                bool
	runtimesConfig      commonutils.RuntimesSocketPathConfig
	nodeSelector        string
)

var supportedHooks = []string{"auto", "crio", "podinformer", "nri", "fanotify"}

func init() {
	commonutils.AddRuntimesSocketPathFlags(deployCmd, &runtimesConfig)

	deployCmd.PersistentFlags().StringVarP(
		&image,
		"image", "",
		gadgetimage,
		"container image")
	deployCmd.PersistentFlags().StringVarP(
		&imagePullPolicy,
		"image-pull-policy", "",
		"Always",
		"pull policy for the container image")
	deployCmd.PersistentFlags().StringVarP(
		&hookMode,
		"hook-mode", "",
		"auto",
		"how to get containers start/stop notifications (auto, crio, podinformer, nri, fanotify)")
	deployCmd.PersistentFlags().BoolVarP(
		&livenessProbe,
		"liveness-probe", "",
		true,
		"enable liveness probes")
	deployCmd.PersistentFlags().BoolVarP(
		&fallbackPodInformer,
		"fallback-podinformer", "",
		true,
		"use pod informer as a fallback for the main hook")
	deployCmd.PersistentFlags().BoolVarP(
		&printOnly,
		"print-only", "",
		false,
		"only print YAML of resources")
	deployCmd.PersistentFlags().BoolVarP(
		&wait,
		"wait", "",
		true,
		"wait for gadget pod to be ready")
	deployCmd.PersistentFlags().DurationVarP(
		&deployTimeout,
		"timeout", "",
		120*time.Second,
		"timeout for deployment")
	// TODO: Combine --quiet and --debug in --verbose LEVEL?
	deployCmd.PersistentFlags().BoolVarP(
		&quiet,
		"quiet", "q",
		false,
		"supress information messages")
	deployCmd.PersistentFlags().BoolVarP(
		&debug,
		"debug", "d",
		false,
		"show extra debug information")
	deployCmd.PersistentFlags().StringVarP(
		&nodeSelector,
		"node-selector", "",
		"",
		"node labels selector for the Inspektor Gadget DaemonSet")
	rootCmd.AddCommand(deployCmd)
}

func info(format string, args ...any) {
	if quiet {
		return
	}
	fmt.Printf(format, args...)
}

// parseK8sYaml parses a k8s YAML deployment file content and returns the
// corresponding objects.
// It was adapted from:
// https://github.com/kubernetes/client-go/issues/193#issuecomment-363318588
func parseK8sYaml(content string) ([]runtime.Object, error) {
	sepYamlfiles := strings.Split(content, "---")
	retVal := make([]runtime.Object, 0, len(sepYamlfiles))

	sch := runtime.NewScheme()

	// For CustomResourceDefinition kind.
	apiextv1.AddToScheme(sch)
	// For all the other kinds (e.g. Namespace).
	scheme.AddToScheme(sch)

	for _, f := range sepYamlfiles {
		if f == "\n" || f == "" {
			// ignore empty cases
			continue
		}

		decode := serializer.NewCodecFactory(sch).UniversalDeserializer().Decode
		obj, _, err := decode([]byte(f), nil, nil)
		if err != nil {
			return nil, fmt.Errorf("error while decoding YAML object: %w", err)
		}

		retVal = append(retVal, obj)
	}

	return retVal, nil
}

// stringToPullPolicy returns the PullPolicy corresponding to the given string
// or an error if there is no corresponding policy.
func stringToPullPolicy(imagePullPolicy string) (v1.PullPolicy, error) {
	switch imagePullPolicy {
	case "Always":
		return v1.PullAlways, nil
	case "Never":
		return v1.PullNever, nil
	case "IfNotPresent":
		return v1.PullIfNotPresent, nil
	default:
		return "", fmt.Errorf("invalid pull policy: %s. Possible values are [Always, Never, IfNotPresent]",
			imagePullPolicy)
	}
}

// createOrUpdateResource creates or updates the resource corresponding
// to the object given as parameter using a dynamic client a RESTMapper
// to get the corresponding resource.
// It is inspired from:
// https://ymmt2005.hatenablog.com/entry/2020/04/14/An_example_of_using_dynamic_client_of_k8s.io/client-go#Dynamic-client
func createOrUpdateResource(client dynamic.Interface, mapper meta.RESTMapper, object runtime.Object) (*unstructured.Unstructured, error) {
	groupVersionKind := object.GetObjectKind().GroupVersionKind()
	mapping, err := mapper.RESTMapping(groupVersionKind.GroupKind(), groupVersionKind.Version)
	if err != nil {
		return nil, err
	}

	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil, fmt.Errorf("failed to convert object to untrusctured: %w", err)
	}

	unstruct := &unstructured.Unstructured{Object: unstructuredObj}

	var dynamicInterface dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dynamicInterface = client.Resource(mapping.Resource).Namespace(unstruct.GetNamespace())
	} else {
		dynamicInterface = client.Resource(mapping.Resource)
	}

	info("Creating %s/%s...\n", unstruct.GetKind(), unstruct.GetName())

	data, err := json.Marshal(unstruct)
	if err != nil {
		return nil, err
	}

	obj, err := dynamicInterface.Patch(context.TODO(), unstruct.GetName(), types.ApplyPatchType, data, metav1.PatchOptions{
		FieldManager: "kubectl-gadget",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create %q: %w", groupVersionKind.Kind, err)
	}

	return obj, nil
}

// Based on https://github.com/kubernetes/kubernetes/issues/98256#issue-790804261
func operatorAsNodeSelectorOperator(sop selection.Operator) (v1.NodeSelectorOperator, error) {
	switch sop {
	case selection.DoesNotExist:
		return v1.NodeSelectorOpDoesNotExist, nil
	case selection.Equals, selection.DoubleEquals, selection.In:
		return v1.NodeSelectorOpIn, nil
	case selection.NotEquals, selection.NotIn:
		return v1.NodeSelectorOpNotIn, nil
	case selection.Exists:
		return v1.NodeSelectorOpExists, nil
	case selection.GreaterThan:
		return v1.NodeSelectorOpGt, nil
	case selection.LessThan:
		return v1.NodeSelectorOpLt, nil
	default:
		return v1.NodeSelectorOpIn, fmt.Errorf("%q is not a valid node selector operator", sop)
	}
}

func selectorAsNodeSelector(s string) (*v1.NodeSelector, error) {
	selector, err := labels.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parsing labels: %w", err)
	}

	nreqs := []v1.NodeSelectorRequirement{}
	reqs, _ := selector.Requirements()
	for _, req := range reqs {
		operator, err := operatorAsNodeSelectorOperator(req.Operator())
		if err != nil {
			return nil, err
		}
		nreq := v1.NodeSelectorRequirement{
			Key:      req.Key(),
			Operator: operator,
			Values:   req.Values().List(),
		}
		nreqs = append(nreqs, nreq)
	}
	nodeSelector := &v1.NodeSelector{
		NodeSelectorTerms: []v1.NodeSelectorTerm{
			{
				MatchExpressions: nreqs,
			},
		},
	}
	return nodeSelector, nil
}

// createAffinity returns the affinity to be used for the DaemonSet.
func createAffinity(client *kubernetes.Clientset) (*v1.Affinity, error) {
	nodes, err := client.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: nodeSelector})
	if err != nil {
		return nil, fmt.Errorf("listing nodes: %w", err)
	}

	if len(nodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found for labels: %q", nodeSelector)
	}

	nodeSelector, err := selectorAsNodeSelector(nodeSelector)
	if err != nil {
		return nil, err
	}

	affinity := &v1.Affinity{
		NodeAffinity: &v1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: nodeSelector,
		},
	}

	return affinity, nil
}

func runDeploy(cmd *cobra.Command, args []string) error {
	found := false
	for _, supportedHook := range supportedHooks {
		if hookMode == supportedHook {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("invalid argument %q for --hook-mode=[%s]", hookMode, strings.Join(supportedHooks, ","))
	}

	if quiet && debug {
		return fmt.Errorf("it's not possible to use --quiet and --debug together")
	}

	objects, err := parseK8sYaml(resources.GadgetDeployment)
	if err != nil {
		return err
	}

	traceObjects, err := parseK8sYaml(resources.TracesCustomResource)
	if err != nil {
		return err
	}

	objects = append(objects, traceObjects...)

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return fmt.Errorf("failed to create RESTConfig: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(discoveryClient))

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return fmt.Errorf("failed to create dynamic client: %w", err)
	}

	k8sClient, err := k8sutil.NewClientsetFromConfigFlags(utils.KubernetesConfigFlags)
	if err != nil {
		return commonutils.WrapInErrSetupK8sClient(err)
	}

	for _, object := range objects {
		var currentGadgetDS *appsv1.DaemonSet

		daemonSet, handlingDaemonSet := object.(*appsv1.DaemonSet)
		if handlingDaemonSet {
			daemonSet.Spec.Template.Annotations["inspektor-gadget.kinvolk.io/option-hook-mode"] = hookMode

			if !printOnly {
				// The "kubernetes.io/os" node label was introduced in v1.14.0
				// (https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG/CHANGELOG-1.14.md.)
				// Remove this if the cluster is older than that to allow Inspektor Gadget to work there.
				serverInfo, err := discoveryClient.ServerVersion()
				if err != nil {
					return fmt.Errorf("getting server version: %w", err)
				}

				serverVersion := k8sversion.MustParseSemantic(serverInfo.String())
				if serverVersion.LessThan(k8sversion.MustParseSemantic("v1.14.0")) {
					delete(daemonSet.Spec.Template.Spec.NodeSelector, "kubernetes.io/os")
				}
			}

			gadgetContainer := &daemonSet.Spec.Template.Spec.Containers[0]

			gadgetContainer.Image = image

			policy, err := stringToPullPolicy(imagePullPolicy)
			if err != nil {
				return err
			}
			gadgetContainer.ImagePullPolicy = policy

			if !livenessProbe {
				gadgetContainer.LivenessProbe = nil
			}

			for i := range gadgetContainer.Env {
				switch gadgetContainer.Env[i].Name {
				case "GADGET_IMAGE":
					gadgetContainer.Env[i].Value = image
				case "INSPEKTOR_GADGET_VERSION":
					gadgetContainer.Env[i].Value = version
				case "INSPEKTOR_GADGET_OPTION_HOOK_MODE":
					gadgetContainer.Env[i].Value = hookMode
				case "INSPEKTOR_GADGET_OPTION_FALLBACK_POD_INFORMER":
					gadgetContainer.Env[i].Value = strconv.FormatBool(fallbackPodInformer)
				case utils.GadgetEnvironmentContainerdSocketpath:
					gadgetContainer.Env[i].Value = runtimesConfig.Containerd
				case utils.GadgetEnvironmentCRIOSocketpath:
					gadgetContainer.Env[i].Value = runtimesConfig.Crio
				case utils.GadgetEnvironmentDockerSocketpath:
					gadgetContainer.Env[i].Value = runtimesConfig.Docker
				case utils.GadgetEnvironmentPodmanSocketpath:
					gadgetContainer.Env[i].Value = runtimesConfig.Podman
				}
			}

			if nodeSelector != "" {
				affinity, err := createAffinity(k8sClient)
				if err != nil {
					return fmt.Errorf("creating affinity: %w", err)
				}
				daemonSet.Spec.Template.Spec.Affinity = affinity
			}

			// Get gadget daemon set (if any) to check if it was modified
			currentGadgetDS, _ = k8sClient.AppsV1().DaemonSets(utils.GadgetNamespace).Get(
				context.TODO(), "gadget", metav1.GetOptions{},
			)
		}

		if printOnly {
			bytes, err := yaml.Marshal(object)
			if err != nil {
				return fmt.Errorf("problem while marshaling object: %w", err)
			}
			fmt.Printf("%s---\n", bytes)
			continue
		}

		obj, err := createOrUpdateResource(dynamicClient, mapper, object)
		if err != nil {
			return fmt.Errorf("problem while creating resource: %w", err)
		}

		if handlingDaemonSet {
			var appliedGadgetDS appsv1.DaemonSet
			err := runtime.DefaultUnstructuredConverter.FromUnstructured(obj.Object, &appliedGadgetDS)
			if err != nil {
				return fmt.Errorf("failed to convert data: %w", err)
			}

			// If the spec of the DaemonSet is the same just return
			if reflect.DeepEqual(currentGadgetDS.Spec, appliedGadgetDS.Spec) {
				info("The gadget pod(s) weren't modified!\n")
				return nil
			}
		}
	}

	if printOnly {
		return nil
	}
	if !wait {
		info("Inspektor Gadget is being deployed\n")
		return nil
	}

	info("Waiting for gadget pod(s) to be ready...\n")

	// The below code (particularly how to use UntilWithSync) is highly
	// inspired from kubectl wait source code:
	// https://github.com/kubernetes/kubectl/blob/b5fe0f6e9c65ea95a2118746b7e04822255d76c2/pkg/cmd/wait/wait.go#L364
	daemonSetInterface := k8sClient.AppsV1().DaemonSets(utils.GadgetNamespace)
	lw := &cache.ListWatch{
		ListFunc: func(options metav1.ListOptions) (runtime.Object, error) {
			options.LabelSelector = "k8s-app=gadget"

			return daemonSetInterface.List(context.TODO(), options)
		},
		WatchFunc: func(options metav1.ListOptions) (watch.Interface, error) {
			options.LabelSelector = "k8s-app=gadget"

			return daemonSetInterface.Watch(context.TODO(), options)
		},
	}

	ctx, cancel := watchtools.ContextWithOptionalTimeout(context.TODO(), deployTimeout)
	defer cancel()

	_, err = watchtools.UntilWithSync(ctx, lw, &appsv1.DaemonSet{}, nil, func(event watch.Event) (bool, error) {
		switch event.Type {
		case watch.Deleted:
			return false, fmt.Errorf("DaemonSet from namespace %s should not be deleted", utils.GadgetNamespace)
		case watch.Modified:
			daemonSet, _ := event.Object.(*appsv1.DaemonSet)
			status := daemonSet.Status

			ready := status.NumberReady
			if status.UpdatedNumberScheduled < ready {
				ready = status.UpdatedNumberScheduled
			}

			info("%d/%d gadget pod(s) ready\n", ready, status.DesiredNumberScheduled)

			return (status.DesiredNumberScheduled == status.NumberReady) &&
				(status.DesiredNumberScheduled == status.UpdatedNumberScheduled), nil
		case watch.Error:
			// Deal particularly with error.
			return false, fmt.Errorf("received event is an error one: %v", event)
		default:
			// We are not interested in other event types.
			return false, nil
		}
	})

	if err != nil {
		if utilwait.Interrupted(err) && debug {
			fmt.Println("DUMP PODS:")
			fmt.Println(getGadgetPodsDebug(k8sClient))
			fmt.Println("DUMP EVENTS:")
			fmt.Println(getEvents(k8sClient))
		}
		return err
	}

	info("Retrieving Gadget Catalog...\n")
	err = grpcruntime.New(true).UpdateCatalog()
	if err != nil {
		fmt.Printf("> failed: %v\n", err)
	}

	info("Inspektor Gadget successfully deployed\n")

	return nil
}
