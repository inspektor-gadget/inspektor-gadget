// Copyright 2023 The Inspektor Gadget authors
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
	"os"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const FilePrefix = "@"

// Param is a wrapper around params.Param. It's used to implement the logic that reads parameters from files.
type Param struct {
	*params.Param
}

func (p *Param) Set(val string) error {
	if strings.HasPrefix(val, FilePrefix) {
		filepath := strings.TrimPrefix(val, FilePrefix)
		data, err := os.ReadFile(filepath)
		if err != nil {
			return fmt.Errorf("reading file %q for parameter %q: %w", filepath, p.Key, err)
		}
		return p.Param.Set(string(data))
	}
	return p.Param.Set(val)
}
