// Copyright 2022 The Inspektor Gadget authors
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

package types

import (
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	ProfileUserParam   = "user"
	ProfileKernelParam = "kernel"
)

type Report struct {
	eventtypes.CommonData

	Comm        string   `json:"comm,omitempty"`
	Pid         uint32   `json:"pid,omitempty"`
	UserStack   []string `json:"user_stack,omitempty"`
	KernelStack []string `json:"kernel_stack,omitempty"`
	Count       uint64   `json:"count,omitempty"`
}

// GetBaseEvent is defined to implement the commonutils.BaseElement interface so
// that we can use the commonutils.BaseParser methods to parse Report. In
// commonutils.BaseParser.Transform(), we call GetBaseEvent() to check whether
// the element being parsed is a special event or not. Given that the profile
// cpu gadget is not event-based, this method simply returns nil.
func (e Report) GetBaseEvent() *eventtypes.Event {
	return nil
}
