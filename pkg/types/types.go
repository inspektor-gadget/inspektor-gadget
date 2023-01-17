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

package types

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

type EventType string

var node string

func init() {
	// Register column templates
	columns.MustRegisterTemplate("timestamp", "width:35,maxWidth:35,hide")
	columns.MustRegisterTemplate("node", "width:30,ellipsis:middle")
	columns.MustRegisterTemplate("namespace", "width:30")
	columns.MustRegisterTemplate("pod", "width:30,ellipsis:middle")
	columns.MustRegisterTemplate("container", "width:30")
	columns.MustRegisterTemplate("comm", "maxWidth:16")
	columns.MustRegisterTemplate("pid", "minWidth:7")
	columns.MustRegisterTemplate("ns", "width:12,hide")

	// For IPs (IPv4+IPv6):
	// Min: XXX.XXX.XXX.XXX (IPv4) = 15
	// Max: 0000:0000:0000:0000:0000:ffff:XXX.XXX.XXX.XXX (IPv4-mapped IPv6 address) = 45
	columns.MustRegisterTemplate("ipaddr", "minWidth:15,maxWidth:45")
	columns.MustRegisterTemplate("ipport", "minWidth:type")

	// For system calls as the longest is sched_rr_get_interval_time64 with 28
	// characters:
	// https://gist.github.com/alban/aa664b3c46aaf24aeb69caae29a01ae5
	// But there is a lot of system calls which name is below 18 characters.
	columns.MustRegisterTemplate("syscall", "width:18,maxWidth:28")
}

func Init(nodeName string) {
	node = nodeName
}

type Time int64

func (t Time) String() string {
	// Don't use time.RFC3339Nano because we prefer to keep the trailing
	// zeros for alignment
	return time.Unix(0, int64(t)).Format("2006-01-02T15:04:05.000000000Z07:00")
}

type CommonData struct {
	// Node where the event comes from
	Node string `json:"node,omitempty" column:"node,template:node" columnTags:"kubernetes"`

	// Pod namespace where the event comes from, or empty for host-level
	// event
	Namespace string `json:"namespace,omitempty" column:"namespace,template:namespace" columnTags:"kubernetes"`

	// Pod where the event comes from, or empty for host-level event
	Pod string `json:"pod,omitempty" column:"pod,template:pod" columnTags:"kubernetes"`

	// Container where the event comes from, or empty for host-level or
	// pod-level event
	Container string `json:"container,omitempty" column:"container,template:container" columnTags:"kubernetes,runtime"`
}

func (c *CommonData) SetNode(node string) {
	c.Node = node
}

func (c *CommonData) SetContainerInfo(pod, namespace, container string) {
	c.Pod = pod
	c.Namespace = namespace
	c.Container = container
}

const (
	// Indicates a generic event produced by a gadget. Gadgets extend
	// the base event to contain the specific data the gadget provides
	NORMAL EventType = "normal"

	// Event is an error message
	ERR EventType = "err"

	// Event is a warning message
	WARN EventType = "warn"

	// Event is a debug message
	DEBUG EventType = "debug"

	// Event is a info message
	INFO EventType = "info"

	// Indicates the tracer in the node is now is able to produce events
	READY EventType = "ready"
)

type Event struct {
	CommonData

	// Timestamp in nanoseconds since January 1, 1970 UTC. An int64 is big
	// enough to represent time between the year 1678 and 2262.
	Timestamp Time `json:"timestamp,omitempty" column:"timestamp,template:timestamp,stringer"`

	// Type indicates the kind of this event
	Type EventType `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`
}

// GetBaseEvent is needed to implement commonutils.BaseElement and
// snapshot.SnapshotEvent interfaces.
func (e Event) GetBaseEvent() *Event {
	return &e
}

func Err(msg string) Event {
	return Event{
		CommonData: CommonData{
			Node: node,
		},
		Type:    ERR,
		Message: msg,
	}
}

func Warn(msg string) Event {
	return Event{
		CommonData: CommonData{
			Node: node,
		},
		Type:    WARN,
		Message: msg,
	}
}

func Debug(msg string) Event {
	return Event{
		CommonData: CommonData{
			Node: node,
		},
		Type:    DEBUG,
		Message: msg,
	}
}

func Info(msg string) Event {
	return Event{
		CommonData: CommonData{
			Node: node,
		},
		Type:    INFO,
		Message: msg,
	}
}

func EventString(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		return fmt.Sprintf("error marshalling event: %s\n", err)
	}
	return string(b)
}

type MountNsID struct {
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns"`
}

func (e *MountNsID) GetMountNSID() uint64 {
	return e.MountNsID
}

func (e *Event) GetTimestamp() int64 {
	return int64(e.Timestamp)
}
