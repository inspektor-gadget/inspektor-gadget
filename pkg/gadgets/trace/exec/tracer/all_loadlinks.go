// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build linux && !arm64 && !withoutebpf

package tracer

import (
	"fmt"

	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
)

func loadExecsnoopLinks(objs execsnoopObjects) (link.Link, link.Link, error) {
	enter, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.IgExecveE, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	exit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.IgExecveX, nil)
	if err != nil {
		gadgets.CloseLink(enter)
		return nil, nil, fmt.Errorf("error opening tracepoint: %w", err)
	}

	return enter, exit, nil
}
