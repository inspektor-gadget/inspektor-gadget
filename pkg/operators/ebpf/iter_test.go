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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIteratorKind(t *testing.T) {
	for _, tt := range []struct {
		name      string
		kind      string
		supported bool
		perPidNs  bool
		perNetNs  bool
	}{
		{name: "tasks", kind: "task", supported: true, perPidNs: true},
		{name: "task files", kind: "task_file", supported: true, perPidNs: true},
		{name: "task memory areas", kind: "task_vma", supported: true, perPidNs: true},
		{name: "tcp sockets", kind: "tcp", supported: true, perNetNs: true},
		{name: "udp sockets", kind: "udp", supported: true, perNetNs: true},
		{name: "kernel symbols", kind: "ksym", supported: true},
		{name: "map elements", kind: "bpf_map_elem", supported: true},
		{name: "unsupported kernel iterator", kind: "bpf_prog"},
		{name: "unknown iterator", kind: "unknown"},
		{name: "empty kind"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.supported, isIteratorKindSupported(tt.kind))
			require.Equal(t, tt.perPidNs, isIteratorKindPerPidNs(tt.kind))
			require.Equal(t, tt.perNetNs, isIteratorKindPerNetNs(tt.kind))
		})
	}
}
