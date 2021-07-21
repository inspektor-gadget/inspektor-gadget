// Copyright 2019-2021 The Inspektor Gadget authors
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

package gadgets

import (
	"fmt"

	"k8s.io/apimachinery/pkg/types"
)

const (
	PIN_PATH         = "/sys/fs/bpf/gadget"
	MNTMAP_PREFIX    = "mntnsset_"
	CGROUPMAP_PREFIX = "cgroupidset_"

	// The Trace custom resource is preferably in the "gadget" namespace
	TRACE_DEFAULT_NAMESPACE = "gadget"
)

func TraceNameFromNamespacedName(n types.NamespacedName) string {
	return "trace_" + n.Namespace + "_" + n.Name
}

func TracePinPathFromNamespacedName(n types.NamespacedName) string {
	return fmt.Sprintf("%s/%s%s", PIN_PATH, MNTMAP_PREFIX, TraceNameFromNamespacedName(n))
}
