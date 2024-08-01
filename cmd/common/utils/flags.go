// Copyright 2022 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

const (
	OutputModeColumns    = "columns"
	OutputModeJSON       = "json"
	OutputModeJSONPretty = "jsonpretty"
	OutputModeYAML       = "yaml"
)

var SupportedOutputModes = []string{OutputModeJSON, OutputModeColumns}

// OutputConfig contains the flags that describes how to print the gadget's output
type OutputConfig struct {
	// OutputMode specifies the format output should be printed
	OutputMode string

	// List of columns to print (only meaningful when OutputMode is "columns=...")
	CustomColumns []string

	// Verbose prints additional information
	Verbose bool
}

func AddOutputFlags(command *cobra.Command, outputConfig *OutputConfig) {
	command.PersistentFlags().StringVarP(
		&outputConfig.OutputMode,
		"output",
		"o",
		"",
		fmt.Sprintf("Output format (%s).", strings.Join(SupportedOutputModes, ", ")),
	)

	command.PersistentFlags().BoolVarP(
		&outputConfig.Verbose,
		"verbose", "v",
		false,
		"Print debug information",
	)
}

func (config *OutputConfig) ParseOutputConfig() error {
	if config.Verbose {
		log.StandardLogger().SetLevel(log.DebugLevel)
	}

	switch {
	case len(config.OutputMode) == 0:
		config.OutputMode = OutputModeColumns
		return nil
	case config.OutputMode == OutputModeJSON:
		return nil
	case strings.HasPrefix(config.OutputMode, OutputModeColumns):
		parts := strings.Split(config.OutputMode, "=")
		if len(parts) != 2 {
			return WrapInErrInvalidArg(OutputModeColumns,
				errors.New("expects a comma separated list of columns to use"))
		}

		cols := strings.Split(strings.ToLower(parts[1]), ",")
		for _, col := range cols {
			if len(col) == 0 {
				return WrapInErrInvalidArg(OutputModeColumns,
					errors.New("column can't be empty"))
			}
		}

		config.CustomColumns = cols
		config.OutputMode = OutputModeColumns
		return nil
	default:
		return WrapInErrOutputModeNotSupported(config.OutputMode)
	}
}

type RuntimesSocketPathConfig struct {
	Docker     string
	Containerd string
	Crio       string
	Podman     string
}

func AddRuntimesSocketPathFlags(command *cobra.Command, config *RuntimesSocketPathConfig) {
	command.PersistentFlags().StringVarP(
		&config.Docker,
		"docker-socketpath", "",
		runtimeclient.DockerDefaultSocketPath,
		"Docker Engine API Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&config.Containerd,
		"containerd-socketpath", "",
		runtimeclient.ContainerdDefaultSocketPath,
		"containerd CRI Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&config.Crio,
		"crio-socketpath", "",
		runtimeclient.CrioDefaultSocketPath,
		"CRI-O CRI Unix socket path",
	)

	command.PersistentFlags().StringVarP(
		&config.Podman,
		"podman-socketpath", "",
		runtimeclient.PodmanDefaultSocketPath,
		"Podman Unix socket path",
	)
}

func AddRegistryAuthVariablesAndFlags(cmd *cobra.Command, authOptions *oci.AuthOptions) {
	// Flag inspired by https://github.com/containers/common/blob/cac40138f7e3c2b29ca32e64348535516bf6aa51/pkg/auth/cli.go#L48
	cmd.Flags().StringVar(
		&authOptions.AuthFile,
		"authfile",
		oci.DefaultAuthFile,
		"Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable",
	)
	viper.BindPFlag("registry.auth_file", cmd.Flags().Lookup("authfile"))
	viper.BindEnv("registry.auth_file", "REGISTRY_AUTH_FILE")

	cmd.Flags().StringSliceVar(
		&authOptions.InsecureRegistries,
		"insecure-registries",
		[]string{},
		"List of registries to access over plain HTTP",
	)
}

// removeSplitSortArgs removes the --sort flag with its arg, if it isn't in the
// merged form of --sort=foo
func removeSplitSortArgs(args []string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--sort" {
			// Remove also the next element as it is the arg of --sort
			return append(args[:i], args[i+2:]...)
		}
	}
	return args
}

// removeHelpArg removes the --help flag
func removeHelpArg(args []string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--help" || args[i] == "-h" {
			return append(args[:i], args[i+1:]...)
		}
	}
	return args
}

func ParseEarlyFlags(cmd *cobra.Command, rawArgs []string) error {
	// Do not error out on unknown flags, but still validate currently
	// known ones.
	// Other flags will be validated in the `Execute()` call and unknown
	// ones will be rejected

	cmd.FParseErrWhitelist.UnknownFlags = true
	defer func() {
		cmd.FParseErrWhitelist.UnknownFlags = false
	}()
	// temporary workaround for https://github.com/inspektor-gadget/inspektor-gadget/pull/2174#issuecomment-1780923952
	args := slices.Clone(rawArgs) // clone to avoid modifying the original os.Args
	args = removeSplitSortArgs(args)
	// --help should be handled after we registered all commands
	args = removeHelpArg(args)
	err := cmd.ParseFlags(args)
	return err
}

func CopyFlagSet(fs *pflag.FlagSet) *pflag.FlagSet {
	flags := pflag.NewFlagSet("", pflag.ContinueOnError)
	flags.AddFlagSet(fs)
	return flags
}
