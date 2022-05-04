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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	auditseccomp "github.com/kinvolk/inspektor-gadget/pkg/gadgets/audit-seccomp"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biolatency"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biotop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/capabilities"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/execsnoop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/filetop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/fsslower"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/mountsnoop"
	networkpolicyadvisor "github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/oomkill"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop"
	processcollector "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/profile"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/sigsnoop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/snisnoop"
	socketcollector "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcpconnect"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcptop"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/tcptracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/traceloop"
)

func TraceFactories() map[string]gadgets.TraceFactory {
	return map[string]gadgets.TraceFactory{
		"audit-seccomp":          auditseccomp.NewFactory(),
		"bindsnoop":              bindsnoop.NewFactory(),
		"biolatency":             biolatency.NewFactory(),
		"biotop":                 biotop.NewFactory(),
		"capabilities":           capabilities.NewFactory(),
		"dns":                    dns.NewFactory(),
		"execsnoop":              execsnoop.NewFactory(),
		"filetop":                filetop.NewFactory(),
		"fsslower":               fsslower.NewFactory(),
		"opensnoop":              opensnoop.NewFactory(),
		"mountsnoop":             mountsnoop.NewFactory(),
		"network-policy-advisor": networkpolicyadvisor.NewFactory(),
		"oomkill":                oomkill.NewFactory(),
		"process-collector":      processcollector.NewFactory(),
		"profile":                profile.NewFactory(),
		"seccomp":                seccomp.NewFactory(),
		"sigsnoop":               sigsnoop.NewFactory(),
		"snisnoop":               snisnoop.NewFactory(),
		"socket-collector":       socketcollector.NewFactory(),
		"tcpconnect":             tcpconnect.NewFactory(),
		"tcptop":                 tcptop.NewFactory(),
		"tcptracer":              tcptracer.NewFactory(),
		"traceloop":              traceloop.NewFactory(),
	}
}

func TraceFactoriesForLocalGadget() map[string]gadgets.TraceFactory {
	return map[string]gadgets.TraceFactory{
		"audit-seccomp":    auditseccomp.NewFactory(),
		"dns":              dns.NewFactory(),
		"socket-collector": socketcollector.NewFactory(),
		"seccomp":          seccomp.NewFactory(),
		"snisnoop":         snisnoop.NewFactory(),
	}
}
