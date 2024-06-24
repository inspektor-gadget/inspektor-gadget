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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/config"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
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
