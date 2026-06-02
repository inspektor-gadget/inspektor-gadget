// Copyright 2024 The Inspektor Gadget authors
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

package common

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

// NewDaemonConfigCmd creates the `daemon-config` root command with subcommands.
func NewDaemonConfigCmd(runtime runtime.Runtime, rootFlags *pflag.FlagSet) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "daemon-config",
		Short: "Daemon configuration commands",
	}

	defaultCmd := &cobra.Command{
		Use:          "default",
		Short:        "Print the default daemon configuration",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
	}

	viewCmd := &cobra.Command{
		Use:          "view",
		Short:        "Print the current daemon configuration",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
	}


	defaultCmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg := viper.New()
		operatorConfig := map[string]any{} 

		// Global params
		ociGlobalParams := apihelpers.ToParamDescs(ocihandler.OciHandler.GlobalParams()).ToParams()
		ociConfig := map[string]any{}
		ociGlobalParams.CopyToMapExt(ociConfig, "")

		// Instance params
		ociInstanceParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()
		ociInstanceParams.CopyToMapExt(ociConfig, "") // merge into same map

		operatorConfig["oci"] = ociConfig
		cfg.Set("operator", operatorConfig)

		yamlData, err := yaml.Marshal(cfg.AllSettings())
		if err != nil {
			return fmt.Errorf("marshalling daemon default config: %w", err)
		}
		fmt.Print(string(yamlData))
		return nil
	}

	viewCmd.RunE = func(cmd *cobra.Command, args []string) error {
		yamlData, err := yaml.Marshal(config.Config.AllSettings())
		if err != nil {
			return fmt.Errorf("marshalling current daemon config: %w", err)
		}

		fmt.Print(string(yamlData))
		return nil
	}

	cmd.AddCommand(defaultCmd)
	cmd.AddCommand(viewCmd)

	return cmd
}
