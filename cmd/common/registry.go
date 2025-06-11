// Copyright 2022-2024 The Inspektor Gadget authors
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
	"strings"

	"github.com/spf13/cobra"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func mustSkip(skipParams []params.ValueHint, valueHint params.ValueHint) bool {
	for _, param := range skipParams {
		if param == valueHint {
			return true
		}
	}
	return false
}

func AddFlags(cmd *cobra.Command, params *params.Params, skipParams []params.ValueHint, runtime runtime.Runtime) {
	defer func() {
		if err := recover(); err != nil {
			panic(fmt.Sprintf("registering params for command %q: %v", cmd.Use, err))
		}
	}()
	for _, p := range *params {
		desc := p.Description

		if p.ValueHint != "" {
			if mustSkip(skipParams, p.ValueHint) {
				// don't expose this parameter
				continue
			}

			// Try to get a value from the runtime
			if value, hasValue := runtime.GetDefaultValue(p.ValueHint); hasValue {
				p.Set(value)
			}
		}

		if p.PossibleValues != nil {
			desc += " [" + strings.Join(p.PossibleValues, ", ") + "]"
		}

		flag := cmd.PersistentFlags().VarPF(&Param{p}, p.Key, p.Alias, desc)
		if p.IsMandatory {
			cmd.MarkPersistentFlagRequired(p.Key)
		}

		// Allow passing a boolean flag as --foo instead of having to use --foo=true
		if p.IsBoolFlag() {
			flag.NoOptDefVal = "true"
		}
	}
}
