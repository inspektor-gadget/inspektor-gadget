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

package local

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type Runtime struct{}

func New() *Runtime {
	return &Runtime{}
}

func (r *Runtime) Init(globalRuntimeParams *params.Params) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
	}

	err := host.Init(host.Config{})
	if err != nil {
		return err
	}

	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) SetDefaultValue(key params.ValueHint, value string) {
	panic("not supported, yet")
}

func (r *Runtime) GetDefaultValue(key params.ValueHint) (string, bool) {
	return "", false
}
