// Copyright 2019-2022 The Inspektor Gadget authors
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

package gadgetcollection

import (
	"github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets"
	seccomp "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/advise/seccomp"
	auditseccomp "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/audit/seccomp"
	biolatency "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/profile/block-io"
	profile "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/profile/cpu"
	processcollector "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/snapshot/process"
	socketcollector "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/snapshot/socket"
	biotop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/top/block-io"
	ebpftop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/top/ebpf"
	filetop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/top/file"
	tcptop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/top/tcp"
	bindsnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/bind"
	capabilities "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/capabilities"
	dns "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/dns"
	execsnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/exec"
	fsslower "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/fsslower"
	mountsnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/mount"
	networkgraph "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/network"
	oomkill "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/oomkill"
	opensnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/open"
	sigsnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/signal"
	snisnoop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/sni"
	tcptracer "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/tcp"
	tcpconnect "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/trace/tcpconnect"
	traceloop "github.com/kinvolk/inspektor-gadget/pkg/gadget-collection/gadgets/traceloop"
)

func TraceFactories() map[string]gadgets.TraceFactory {
	return map[string]gadgets.TraceFactory{
		"audit-seccomp":     auditseccomp.NewFactory(),
		"bindsnoop":         bindsnoop.NewFactory(),
		"biolatency":        biolatency.NewFactory(),
		"biotop":            biotop.NewFactory(),
		"capabilities":      capabilities.NewFactory(),
		"dns":               dns.NewFactory(),
		"ebpftop":           ebpftop.NewFactory(),
		"execsnoop":         execsnoop.NewFactory(),
		"filetop":           filetop.NewFactory(),
		"fsslower":          fsslower.NewFactory(),
		"opensnoop":         opensnoop.NewFactory(),
		"mountsnoop":        mountsnoop.NewFactory(),
		"network-graph":     networkgraph.NewFactory(),
		"oomkill":           oomkill.NewFactory(),
		"process-collector": processcollector.NewFactory(),
		"profile":           profile.NewFactory(),
		"seccomp":           seccomp.NewFactory(),
		"sigsnoop":          sigsnoop.NewFactory(),
		"snisnoop":          snisnoop.NewFactory(),
		"socket-collector":  socketcollector.NewFactory(),
		"tcpconnect":        tcpconnect.NewFactory(),
		"tcptop":            tcptop.NewFactory(),
		"tcptracer":         tcptracer.NewFactory(),
		"traceloop":         traceloop.NewFactory(),
	}
}

func TraceFactoriesForLocalGadget() map[string]gadgets.TraceFactory {
	return map[string]gadgets.TraceFactory{
		"audit-seccomp":     auditseccomp.NewFactory(),
		"capabilities":      capabilities.NewFactory(),
		"dns":               dns.NewFactory(),
		"ebpftop":           ebpftop.NewFactory(),
		"network-graph":     networkgraph.NewFactory(),
		"process-collector": processcollector.NewFactory(),
		"socket-collector":  socketcollector.NewFactory(),
		"seccomp":           seccomp.NewFactory(),
		"snisnoop":          snisnoop.NewFactory(),
	}
}
