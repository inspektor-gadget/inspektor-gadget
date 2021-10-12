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
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

var (
	KubernetesConfigFlags = genericclioptions.NewConfigFlags(false)
)

func FlagInit(rootCmd *cobra.Command) {
	cobra.OnInitialize(cobraInit)
	KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func cobraInit() {
	viper.AutomaticEnv()
}

const (
	OutputModeDefault = ""
	OutputModeJson    = "json"
)

var outputModeValidValues = map[string]struct{}{
	OutputModeDefault: {},
	OutputModeJson:    {},
}

// CommonFlags contains CLI flags common to several gadgets
type CommonFlags struct {
	// Label allows to filter containers with a label selector in the
	// following format: key1=value1,key2=value2
	Label string

	// Node allows to filter containers by node name
	Node string

	// No 'Namespace' field because it's added automatically by
	// KubernetesConfigFlags.AddFlags(rootCmd.PersistentFlags())

	// AllNamespaces disables the container filtering by namespace
	AllNamespaces bool

	// Podname allows to filter containers by the pod name
	Podname string

	// Containername allows to filter containers by name
	Containername string

	// OutputMode specifies the way output should be printed
	OutputMode string

	// Verbose prints additional information
	Verbose bool
}

// GetNamespace returns the namespace specified by '-n' or the default
// namespace configured in the kubeconfig file.
func GetNamespace() string {
	namespace, _, _ := KubernetesConfigFlags.ToRawKubeConfigLoader().Namespace()
	return namespace
}

func AddCommonFlags(command *cobra.Command, params *CommonFlags) {
	command.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if _, ok := outputModeValidValues[params.OutputMode]; !ok {
			return fmt.Errorf("%q is not a valid value for -o / --output", params.OutputMode)
		}
		return nil
	}

	// do not print usage when there is an error
	command.SilenceUsage = true

	command.PersistentFlags().StringVarP(
		&params.Label,
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
		"",
		"Output format. One of: json",
	)

	command.PersistentFlags().BoolVarP(
		&params.Verbose,
		"verbose",
		"",
		false,
		"Print additional information",
	)
}
