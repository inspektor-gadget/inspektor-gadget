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
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/resources"
	"github.com/spf13/cobra"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/api/core/v1"
	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"
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
	image                     string
	imagePullPolicy           string
	hookMode                  string
	livenessProbe             bool
	livenessProbeInitialDelay int32
	fallbackPodInformer       bool
	printOnly                 bool
)

func init() {
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
	deployCmd.PersistentFlags().Int32VarP(
		&livenessProbeInitialDelay,
		"liveness-probe-initial-delay", "",
		60,
		"liveness probes initial delay")
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
	rootCmd.AddCommand(deployCmd)
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

// createResource creates the resource corresponding to the object given as
// parameter using a dynamic client an RESTMapper to get the corresponding
// resource.
// It is inspired from:
// https://ymmt2005.hatenablog.com/entry/2020/04/14/An_example_of_using_dynamic_client_of_k8s.io/client-go#Dynamic-client
func createResource(client dynamic.Interface, mapper meta.RESTMapper, object runtime.Object) error {
	groupVersionKind := object.GetObjectKind().GroupVersionKind()
	mapping, err := mapper.RESTMapping(groupVersionKind.GroupKind(), groupVersionKind.Version)
	if err != nil {
		return err
	}

	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return fmt.Errorf("failed to convert object to untrusctured: %w", err)
	}

	unstruct := &unstructured.Unstructured{Object: unstructuredObj}

	var dynamicInterface dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		dynamicInterface = client.Resource(mapping.Resource).Namespace(unstruct.GetNamespace())
	} else {
		dynamicInterface = client.Resource(mapping.Resource)
	}

	_, err = dynamicInterface.Create(context.TODO(), unstruct, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create %q: %w", groupVersionKind.Kind, err)
	}

	return nil
}

func runDeploy(cmd *cobra.Command, args []string) error {
	if hookMode != "auto" &&
		hookMode != "crio" &&
		hookMode != "podinformer" &&
		hookMode != "nri" &&
		hookMode != "fanotify" {
		return fmt.Errorf("invalid argument %q for --hook-mode=[auto,crio,podinformer,nri,fanotify]", hookMode)
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

	for _, object := range objects {
		if daemonSet, ok := object.(*appsv1.DaemonSet); ok {
			daemonSet.Spec.Template.Annotations["inspektor-gadget.kinvolk.io/option-hook-mode"] = hookMode

			gadgetContainer := &daemonSet.Spec.Template.Spec.Containers[0]

			gadgetContainer.Image = image

			policy, err := stringToPullPolicy(imagePullPolicy)
			if err != nil {
				return err
			}
			gadgetContainer.ImagePullPolicy = policy

			if !livenessProbe {
				gadgetContainer.LivenessProbe = nil
			} else {
				gadgetContainer.LivenessProbe.InitialDelaySeconds = livenessProbeInitialDelay
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
				}
			}
		}

		if printOnly {
			bytes, err := yaml.Marshal(object)
			if err != nil {
				return fmt.Errorf("problem while marshaling object: %w", err)
			}
			fmt.Printf("%s---\n", bytes)
		} else {
			err := createResource(dynamicClient, mapper, object)
			if err != nil {
				return fmt.Errorf("problem while creating resource: %w", err)
			}
		}
	}

	return nil
}
