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

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

func TestPopulateSKTargetMap(t *testing.T) {
	instance := &ebpfInstance{
		logger: logger.DefaultLogger(),
		collectionSpec: &ebpf.CollectionSpec{
			Programs: map[string]*ebpf.ProgramSpec{
				"parser": {Type: ebpf.SkSKB},
			},
			Maps: map[string]*ebpf.MapSpec{
				"sockets": {Type: ebpf.SockHash},
				"other":   {Type: ebpf.SockMap},
			},
		},
		skTargetMaps: make(map[string]string),
	}

	require.NoError(t, instance.populateSKTargetMap(nil, "parser___sockets"))
	require.Equal(t, "sockets", instance.skTargetMaps["parser"])
}
