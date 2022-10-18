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

package utils

import (
	"context"
	"fmt"
	"strings"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var KubernetesConfigFlags = genericclioptions.NewConfigFlags(false)

func FlagInit(rootCmd *cobra.Command) {
	cobra.OnInitialize(cobraInit)
	KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func cobraInit() {
	viper.AutomaticEnv()
}

// CommonFlags contains CLI flags common to several gadgets
type CommonFlags struct {
	// OutputConfig describes the way output should be printed
	commonutils.OutputConfig

	// LabelsRaw allows to filter containers with a label selector in the
	// following format: key1=value1,key2=value2.
	// It's the raw representation as passed by the user.
	LabelsRaw string

	// Labels is a parsed representation of LabelsRaw
	Labels map[string]string

	// Node allows to filter containers by node name
	Node string

	// Namespace allows to filter by Kubernetes namespace. Ignored if
	// AllNamespaces is true
	Namespace string

	// NamespaceOverridden will be true only if the CommonFlags.Namespace
	// field contains the value passed by the user using the '-n' flag
	// and not the default value configured in the kubeconfig file.
	NamespaceOverridden bool

	// AllNamespaces disables the container filtering by namespace
	AllNamespaces bool

	// Podname allows to filter containers by the pod name
	Podname string

	// Containername allows to filter containers by name
	Containername string

	// Number of seconds that the gadget will run for
	Timeout int
}

// GetNamespace returns the namespace specified by '-n' or the default
// namespace configured in the kubeconfig file. It also returns a boolean
// that specifies if the namespace comes from the '-n' flag or not.
func GetNamespace() (string, bool) {
	namespace, overridden, _ := KubernetesConfigFlags.ToRawKubeConfigLoader().Namespace()
	return namespace, overridden
}

func AddCommonFlags(command *cobra.Command, params *CommonFlags) {
	command.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		// Namespace
		if !params.AllNamespaces {
			params.Namespace, params.NamespaceOverridden = GetNamespace()
		}

		// Labels
		if params.LabelsRaw != "" {
			params.Labels = make(map[string]string)
			pairs := strings.Split(params.LabelsRaw, ",")
			for _, pair := range pairs {
				kv := strings.Split(pair, "=")
				if len(kv) != 2 {
					return commonutils.WrapInErrInvalidArg("--selector / -l",
						fmt.Errorf("should be a comma-separated list of key-value pairs (key=value[,key=value,...])"))
				}
				params.Labels[kv[0]] = kv[1]
			}
		}

		// Verify that there is a gadget pod running on the node
		// specified in the filter.
		if params.Node != "" {
			client, err := k8sutil.NewClientsetFromConfigFlags(KubernetesConfigFlags)
			if err != nil {
				return commonutils.WrapInErrSetupK8sClient(err)
			}

			opts := metav1.ListOptions{
				LabelSelector: "k8s-app=gadget",
				FieldSelector: "spec.nodeName=" + params.Node,
			}
			pods, err := client.CoreV1().Pods(GadgetNamespace).List(context.TODO(), opts)
			if err != nil {
				return commonutils.WrapInErrListPods(err)
			}

			if len(pods.Items) == 0 {
				return commonutils.WrapInErrInvalidArg("--node",
					fmt.Errorf("there's not a gadget pod in node %q. Does the node exist?",
						params.Node))
			}
		}

		// Output Mode
		if err := params.ParseOutputConfig(); err != nil {
			return err
		}

		return nil
	}

	// do not print usage when there is an error
	command.SilenceUsage = true

	// No 'Namespace' flag because it's added automatically by
	// KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())

	command.PersistentFlags().StringVarP(
		&params.LabelsRaw,
		"selector",
		"l",
		"",
		"Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
	)

	command.PersistentFlags().StringVar(
		&params.Node,
		"node",
		"",
		"Show only data from pods running in that node",
	)

	command.PersistentFlags().StringVarP(
		&params.Podname,
		"podname",
		"p",
		"",
		"Show only data from pods with that name",
	)

	command.PersistentFlags().StringVarP(
		&params.Containername,
		"containername",
		"c",
		"",
		"Show only data from containers with that name",
	)

	command.PersistentFlags().BoolVarP(
		&params.AllNamespaces,
		"all-namespaces",
		"A",
		false,
		"Show data from pods in all namespaces",
	)

	command.PersistentFlags().StringVarP(
		&params.OutputMode,
		"output",
		"o",
		commonutils.OutputModeColumns,
		fmt.Sprintf("Output format (%s).", strings.Join(commonutils.SupportedOutputModes, ", ")),
	)

	command.PersistentFlags().BoolVarP(
		&params.Verbose,
		"verbose",
		"",
		false,
		"Print additional information",
	)

	command.PersistentFlags().IntVarP(
		&params.Timeout,
		"timeout",
		"",
		0,
		"Number of seconds that the gadget will run for",
	)
}
