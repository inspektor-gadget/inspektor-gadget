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
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/viper"
)

func TestPolicyConfigShapes(t *testing.T) {
	for _, tt := range []struct {
		name, yaml string
		invalid    bool
	}{
		{"absent", "", false},
		{"empty policy", "operator:\n  ebpf:\n    policy: {}", false},
		{"empty category", "operator:\n  ebpf:\n    policy:\n      helpers: {}", false},
		{"empty lists", "operator:\n  ebpf:\n    policy:\n      helpers:\n        add: []\n        drop: []", false},
		{"scalar policy", "operator:\n  ebpf:\n    policy: all", true},
		{"unknown category", "operator:\n  ebpf:\n    policy:\n      helper: {}", true},
		{"unknown field", "operator:\n  ebpf:\n    policy:\n      helpers:\n        allow: [all]", true},
		{"scalar category", "operator:\n  ebpf:\n    policy:\n      helpers: all", true},
		{"scalar list", "operator:\n  ebpf:\n    policy:\n      helpers:\n        add: all", true},
		{"number entry", "operator:\n  ebpf:\n    policy:\n      helpers:\n        drop: [123]", true},
		{"null list", "operator:\n  ebpf:\n    policy:\n      helpers:\n        add: null", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			if err := v.ReadConfig(strings.NewReader(tt.yaml)); err != nil {
				t.Fatal(err)
			}
			cfg, err := NewConfigFromViper(v)
			if tt.invalid {
				if err == nil || !strings.Contains(err.Error(), "operator.ebpf.policy") {
					t.Fatalf("expected path error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewPolicy(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyCollectionSpec(policyTestSpec(ebpf.ProgramType(9999), asm.BuiltinFunc(9999).Call()), p); err != nil {
				t.Fatal(err)
			}
		})
	}
	cfg, err := NewConfigFromViper(nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCollectionSpec(nil, p); err != nil {
		t.Fatal(err)
	}
}
