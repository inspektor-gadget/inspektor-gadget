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

import (
	"fmt"
	"sort"

	"github.com/spf13/viper"
)

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
	// Add is the list of BPF helpers to allow (an explicit list starts an allowlist).
	Add []string

	// Drop is the list of BPF helpers to deny from the defaults.
	Drop []string
}

// ProgramTypesConfig defines the add/drop lists for BPF program types.
type ProgramTypesConfig struct {
	// Add is the list of BPF program types to allow (an explicit list starts an allowlist).
	Add []string

	// Drop is the list of BPF program types to deny from the defaults.
	Drop []string
}

// NewConfigFromViper reads administrator policy without Viper's permissive
// string-slice conversions, which can silently discard malformed restrictions.
func NewConfigFromViper(v *viper.Viper) (*Config, error) {
	cfg := &Config{}
	if v == nil || v.Get(ConfigKey+".policy") == nil {
		return cfg, nil
	}
	root, err := policyConfigMap(v.Get(ConfigKey+".policy"), ConfigKey+".policy", []string{"helpers", "programtypes"})
	if err != nil {
		return nil, err
	}
	for _, category := range []string{"helpers", "programtypes"} {
		raw, exists := root[category]
		if !exists {
			continue
		}
		path := ConfigKey + ".policy." + category
		fields, err := policyConfigMap(raw, path, []string{"add", "drop"})
		if err != nil {
			return nil, err
		}
		var lists [2][]string
		for idx, key := range []string{"add", "drop"} {
			raw, exists := fields[key]
			if !exists {
				continue
			}
			switch value := raw.(type) {
			case []string:
				lists[idx] = append([]string(nil), value...)
			case []any:
				for _, entry := range value {
					str, ok := entry.(string)
					if !ok {
						return nil, fmt.Errorf("%s.%s: expected a list of strings", path, key)
					}
					lists[idx] = append(lists[idx], str)
				}
			default:
				return nil, fmt.Errorf("%s.%s: expected a list of strings", path, key)
			}
		}
		if category == "helpers" {
			cfg.Policy.Helpers = HelpersConfig{Add: lists[0], Drop: lists[1]}
		} else {
			cfg.Policy.ProgramTypes = ProgramTypesConfig{Add: lists[0], Drop: lists[1]}
		}
	}
	return cfg, nil
}

func policyConfigMap(raw any, path string, allowed []string) (map[string]any, error) {
	fields, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected a mapping", path)
	}
	var unknown []string
	for key := range fields {
		valid := false
		for _, name := range allowed {
			if key == name {
				valid = true
				break
			}
		}
		if !valid {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return nil, fmt.Errorf("%s.%s: unsupported policy key", path, unknown[0])
	}
	return fields, nil
}
