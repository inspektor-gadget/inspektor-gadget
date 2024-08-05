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
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

var configPath string

// AddConfigFlag adds the --config flag to the command
func AddConfigFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "config file to use")
}

// InitConfig initializes the config by reading the config file and setting root flags
func InitConfig(rootFlags *pflag.FlagSet) error {
	// set the config file path if it is provided
	if configPath != "" {
		config.Config = config.NewWithPath(configPath)
	}

	// we do not want to fail if the config file is not found unless it is explicitly provided
	if err := config.Config.ReadInConfig(); configPath != "" && err != nil {
		return fmt.Errorf("reading config: %w", err)
	}

	// set the root flags based on the config
	var flagErr error
	rootFlags.VisitAll(func(f *pflag.Flag) {
		if f.Name == "config" {
			return
		}

		if err := setFlagsFromConfig(f, f.Name); err != nil {
			flagErr = errors.Join(flagErr, err)
		}
	})

	return flagErr
}

// SetFlagsForParams sets the flags for the given params based on the config
func SetFlagsForParams(cmd *cobra.Command, params *params.Params, configPrefix string) error {
	for k := range params.ParamMap() {
		f := cmd.Flags().Lookup(k)
		if f == nil {
			continue
		}

		configKey := strings.Join([]string{configPrefix, k}, ".")
		if err := setFlagsFromConfig(f, configKey); err != nil {
			return err
		}
	}
	return nil
}

// setFlagsFromConfig sets the flags from the config based on the config key if the flag is not changed
// The precedence order (coming from viper): flag > env > config > default
func setFlagsFromConfig(f *pflag.Flag, k string) error {
	// bind env vars to the flags, if set will override the config file values
	if err := config.Config.BindEnv(k); err != nil {
		return fmt.Errorf("binding env var %s: %w", k, err)
	}

	if !f.Changed && config.Config.IsSet(k) {
		// If the flag's value is a slice, we must set each value individually because the Set() method does not
		// support slice types. Any new values set will be appended to the existing values in the slice.
		// For more details, see: https://github.com/spf13/pflag/blob/master/string_array.go#L21
		if _, ok := f.Value.(pflag.SliceValue); ok {
			vals := config.Config.GetStringSlice(k)
			for _, val := range vals {
				if err := f.Value.Set(val); err != nil {
					return fmt.Errorf("setting flag %s: %w", f.Name, err)
				}
			}
			return nil
		}
		// Handle string slices in a way the params pkg understands it
		if p, ok := f.Value.(*Param); ok && p.TypeHint == params.TypeStringSlice {
			vals := config.Config.GetStringSlice(k)
			return p.Set(strings.Join(vals, ","))
		}

		val := config.Config.GetString(k)
		if val == f.DefValue {
			return nil
		}

		if err := f.Value.Set(val); err != nil {
			return fmt.Errorf("setting flag %s: %w", f.Name, err)
		}
	}
	return nil
}

func NewConfigCmd(runtime runtime.Runtime, rootFlags *pflag.FlagSet) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Configuration commands",
	}
	defaultCmd := &cobra.Command{
		Use:          "default",
		Short:        "Print the default configuration",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
	}
	viewCmd := &cobra.Command{
		Use:          "view",
		Short:        "Print the current configuration",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
	}

	defaultCmd.RunE = func(cmd *cobra.Command, args []string) error {
		defaultConfig := viper.New()
		runtimeConfig := make(map[string]string)
		runtime.GlobalParamDescs().ToParams().CopyToMap(runtimeConfig, "")
		if len(runtimeConfig) > 0 {
			defaultConfig.Set("runtime", runtimeConfig)
		}

		dataOps := operators.GetDataOperators()
		operatorConfig := make(map[string]map[string]any, len(dataOps))
		for _, op := range dataOps {
			opName := strings.ToLower(op.Name())
			opGlobalParams := apihelpers.ToParamDescs(op.GlobalParams()).ToParams()
			if len(opGlobalParams.ParamMap()) == 0 {
				continue
			}
			operatorConfig[opName] = make(map[string]any)
			opGlobalParams.CopyToMapExt(operatorConfig[opName], "")
		}

		_, ok := operatorConfig[ocihandler.OciHandler.Name()]
		if !ok {
			operatorConfig[ocihandler.OciHandler.Name()] = make(map[string]any)
		}
		opInstanceParams := apihelpers.ToParamDescs(ocihandler.OciHandler.InstanceParams()).ToParams()
		opInstanceParams.CopyToMapExt(operatorConfig[ocihandler.OciHandler.Name()], "")
		if len(operatorConfig) > 0 {
			defaultConfig.Set("operator", operatorConfig)
		}

		rootFlags.VisitAll(func(flag *pflag.Flag) {
			if flag.Name == "config" {
				return
			}

			// ensure we set the actual slice value (not string) so users will know they need
			// to set YAML list for array/slice flags. For example, for default value of empty slice
			// we need to set it as `[]` (not `'[]'`) in the config file.
			if sv, ok := flag.Value.(pflag.SliceValue); ok {
				defaultConfig.Set(flag.Name, sv.GetSlice())
				return
			}

			defaultConfig.Set(flag.Name, flag.DefValue)
		})

		cfg, err := yaml.Marshal(defaultConfig.AllSettings())
		if err != nil {
			return fmt.Errorf("marshalling default config: %w", err)
		}

		fmt.Print(string(cfg))
		return nil
	}

	viewCmd.RunE = func(cmd *cobra.Command, args []string) error {
		cfg, err := yaml.Marshal(config.Config.AllSettings())
		if err != nil {
			return fmt.Errorf("marshalling config: %w", err)
		}

		fmt.Print(string(cfg))
		return nil
	}

	cmd.AddCommand(defaultCmd)
	cmd.AddCommand(viewCmd)
	AddConfigFlag(cmd)

	return cmd
}
