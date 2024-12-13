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

package ebpfutils

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

func SpecSetVars(spec *ebpf.CollectionSpec, values map[string]interface{}) error {
	for name, value := range values {
		if err := SpecSetVar(spec, name, value); err != nil {
			return err
		}
	}
	return nil
}

func SpecSetVar(spec *ebpf.CollectionSpec, name string, value interface{}) error {
	v, ok := spec.Variables[name]
	if !ok {
		return fmt.Errorf("variable %q not found on ebpf spec: %w", name, os.ErrNotExist)
	}
	if err := v.Set(value); err != nil {
		return fmt.Errorf("setting %q variable: %w", name, err)
	}

	return nil
}
