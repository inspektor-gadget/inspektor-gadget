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

package allgadgets

import (
	// Advise Category & traceloop are missing for now. They will be added after
	// refactoring the CR handling. Currently, they are still handled by CRs.

	// script can't be added because it's designed only to work in kubectl-gadget for the time
	// being

	// Audit Category
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/tracer"

	// Profile Category
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/tracer"

	// Snapshot Category
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/tracer"

	// Top Category
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/tracer"

	// Trace Category
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/oomkill/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/sni/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcp/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/tracer"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdrop/tracer"
)
