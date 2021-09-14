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

package gadgetcollection

import (
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biolatency"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/dns"
	networkpolicyadvisor "github.com/kinvolk/inspektor-gadget/pkg/gadgets/networkpolicy"
	processcollector "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp"
	socketcollector "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector"
)

func TraceFactories() map[string]gadgets.TraceFactory {
	return map[string]gadgets.TraceFactory{
		"biolatency":             biolatency.NewFactory(),
		"dns":                    dns.NewFactory(),
		"process-collector":      processcollector.NewFactory(),
		"socket-collector":       socketcollector.NewFactory(),
		"seccomp":                seccomp.NewFactory(),
		"network-policy-advisor": networkpolicyadvisor.NewFactory(),
	}
}
