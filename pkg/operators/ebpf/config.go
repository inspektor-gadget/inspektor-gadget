// Copyright 2026 The Inspektor Gadget authors
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

package ebpfoperator

import "github.com/spf13/viper"

const (
	// ConfigKey is the configuration key prefix for the eBPF operator.
	// The configuration structure is:
	//
	//   operator:
	//     ebpf:
	//       policy:
	//         helpers:
	//           add:
	//             - bpf_map_lookup_elem
	//             - bpf_map_update_elem
	//           drop:
	//             - bpf_override_return
	//         programTypes:
	//           add:
	//             - kprobe
	//             - tracepoint
	//           drop:
	//             - xdp
	ConfigKey = "operator.ebpf"
)

// Config represents the configuration for the eBPF operator.
type Config struct {
	// Policy contains the BPF policy configuration for restricting
	// which helpers and program types are allowed.
	Policy PolicyConfigSpec
}

// PolicyConfigSpec defines the policy configuration structure.
type PolicyConfigSpec struct {
	// Helpers defines which BPF helpers are allowed or denied.
	Helpers HelpersConfig

	// ProgramTypes defines which BPF program types are allowed or denied.
	ProgramTypes ProgramTypesConfig
}

// HelpersConfig defines the add/drop lists for BPF helpers.
type HelpersConfig struct {
	// Add is the list of additional BPF helpers to allow beyond the defaults.
	Add []string

	// Drop is the list of BPF helpers to deny from the defaults.
	Drop []string
}

// ProgramTypesConfig defines the add/drop lists for BPF program types.
type ProgramTypesConfig struct {
	// Add is the list of additional BPF program types to allow beyond the defaults.
	Add []string

	// Drop is the list of BPF program types to deny from the defaults.
	Drop []string
}

// NewConfigFromViper creates a Config from a viper configuration.
func NewConfigFromViper(v *viper.Viper) (*Config, error) {
	if v == nil {
		return &Config{}, nil
	}

	cfg := &Config{}

	// Load policy configuration
	cfg.Policy.Helpers.Add = v.GetStringSlice(ConfigKey + ".policy.helpers.add")
	cfg.Policy.Helpers.Drop = v.GetStringSlice(ConfigKey + ".policy.helpers.drop")
	cfg.Policy.ProgramTypes.Add = v.GetStringSlice(ConfigKey + ".policy.programTypes.add")
	cfg.Policy.ProgramTypes.Drop = v.GetStringSlice(ConfigKey + ".policy.programTypes.drop")

	// Set defaults to "all" if not specified
	if len(cfg.Policy.Helpers.Add) == 0 && len(cfg.Policy.Helpers.Drop) == 0 {
		cfg.Policy.Helpers.Add = []string{"all"}
	}
	if len(cfg.Policy.ProgramTypes.Add) == 0 && len(cfg.Policy.ProgramTypes.Drop) == 0 {
		cfg.Policy.ProgramTypes.Add = []string{"all"}
	}

	return cfg, nil
}
