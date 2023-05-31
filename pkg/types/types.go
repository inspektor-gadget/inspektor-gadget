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
	columns.MustRegisterTemplate("uid", "minWidth:8")
	columns.MustRegisterTemplate("gid", "minWidth:8")
	columns.MustRegisterTemplate("ns", "width:12,hide")

	// For IPs (IPv4+IPv6):
	// Min: XXX.XXX.XXX.XXX (IPv4) = 15
	// Max: 0000:0000:0000:0000:0000:ffff:XXX.XXX.XXX.XXX (IPv4-mapped IPv6 address) = 45
	columns.MustRegisterTemplate("ipaddr", "minWidth:15,maxWidth:45")
	columns.MustRegisterTemplate("ipport", "minWidth:type")
	// Assume type width for ipport is 5 characters long. Delimiter is 1. Add that to ipaddr template
	columns.MustRegisterTemplate("ipaddrport", "minWidth:22,width:40,maxWidth:52")
	columns.MustRegisterTemplate("ipversion", "width:2,fixed")

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

type EndpointKind string

const (
	EndpointKindPod     EndpointKind = "pod"
	EndpointKindService EndpointKind = "svc"
	EndpointKindRaw     EndpointKind = "raw"
)

type BasicK8sMetadata struct {
	Namespace string `json:"namespace,omitempty" column:"namespace,template:namespace"`
	PodName   string `json:"podName,omitempty" column:"pod,template:pod"`

	// ContainerName is tagged as "runtime" because we are temporarily using the k8s
	// container name as the container name for "ig list-containers" because the
	// ContainerName struct does not have the runtime container name field.
	ContainerName string `json:"containerName,omitempty" column:"container,template:container" columnTags:"runtime"`
}

type K8sMetadata struct {
	Node string `json:"node,omitempty" column:"node,template:node"`

	BasicK8sMetadata `json:",inline"`

	// HostNetwork is true if the container uses the host network namespace
	HostNetwork bool `json:"hostNetwork,omitempty" column:"hostnetwork,hide"`
}

type CommonData struct {
	// K8s contains the common data for k8s events
	K8s K8sMetadata `json:"k8sMetadata,omitempty" columnTags:"kubernetes"`
}

func (c *CommonData) SetNode(node string) {
	c.K8s.Node = node
}

func (c *CommonData) SetContainerInfo(pod, namespace, container string) {
	c.K8s.PodName = pod
	c.K8s.Namespace = namespace

	// Container may have been enriched before by other means, so don't delete it here,
	// if the incoming info is empty
	if container != "" {
		c.K8s.ContainerName = container
	}
}

func (c *CommonData) GetNode() string {
	return c.K8s.Node
}

func (c *CommonData) GetPod() string {
	return c.K8s.PodName
}

func (c *CommonData) GetNamespace() string {
	return c.K8s.Namespace
}

func (c *CommonData) GetContainer() string {
	return c.K8s.ContainerName
}

type L3Endpoint struct {
	// Addr is filled by the gadget
	Addr string `json:"addr,omitempty" column:"addr,hide,template:ipaddr"`

	// Namespace, Name, Kind and PodLabels get populated by the KubeIPResolver operator
	Namespace string            `json:"namespace,omitempty" column:"ns,template:namespace,hide"`
	Name      string            `json:"podname,omitempty" column:"name,hide"`
	Kind      EndpointKind      `json:"kind,omitempty" column:"kind,hide"`
	PodLabels map[string]string `json:"podlabels,omitempty" column:"podLabels,hide"`
}

func (e *L3Endpoint) String() string {
	switch e.Kind {
	case EndpointKindPod:
		return "p/" + e.Namespace + "/" + e.Name
	case EndpointKindService:
		return "s/" + e.Namespace + "/" + e.Name
	case EndpointKindRaw:
		return "r/" + e.Addr
	default:
		return e.Addr
	}
}

type L4Endpoint struct {
	L3Endpoint
	// Port is filled by the gadget
	Port uint16 `json:"port" column:"port,hide,template:ipport"`
}

func (e *L4Endpoint) String() string {
	return e.L3Endpoint.String() + ":" + fmt.Sprint(e.Port)
}

func MustAddVirtualL4EndpointColumn[Event any](
	cols *columns.Columns[Event],
	attr columns.Attributes,
	getEndpoint func(*Event) L4Endpoint,
) {
	cols.MustAddColumn(
		attr,
		func(e *Event) string {
			endpoint := getEndpoint(e)
			return endpoint.String()
		},
	)
}

func MustAddVirtualL3EndpointColumn[Event any](
	cols *columns.Columns[Event],
	attr columns.Attributes,
	getEndpoint func(*Event) L3Endpoint,
) {
	cols.MustAddColumn(
		attr,
		func(e *Event) string {
			endpoint := getEndpoint(e)
			return endpoint.String()
		},
	)
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

func (e *Event) GetType() EventType {
	return e.Type
}

func (e *Event) GetMessage() string {
	return e.Message
}

func Err(msg string) Event {
	return Event{
		CommonData: CommonData{
			K8s: K8sMetadata{
				Node: node,
			},
		},
		Type:    ERR,
		Message: msg,
	}
}

func Warn(msg string) Event {
	return Event{
		CommonData: CommonData{
			K8s: K8sMetadata{
				Node: node,
			},
		},
		Type:    WARN,
		Message: msg,
	}
}

func Debug(msg string) Event {
	return Event{
		CommonData: CommonData{
			K8s: K8sMetadata{
				Node: node,
			},
		},
		Type:    DEBUG,
		Message: msg,
	}
}

func Info(msg string) Event {
	return Event{
		CommonData: CommonData{
			K8s: K8sMetadata{
				Node: node,
			},
		},
		Type:    INFO,
		Message: msg,
	}
}

func EventString(i interface{}) string {
	b, err := json.Marshal(i)
	if err != nil {
		return fmt.Sprintf("error marshaling event: %s\n", err)
	}
	return string(b)
}

type WithMountNsID struct {
	MountNsID uint64 `json:"mountnsid,omitempty" column:"mntns,template:ns"`
}

func (e *WithMountNsID) GetMountNSID() uint64 {
	return e.MountNsID
}

type WithNetNsID struct {
	NetNsID uint64 `json:"netnsid,omitempty" column:"netns,template:ns"`
}

func (e *WithNetNsID) GetNetNSID() uint64 {
	return e.NetNsID
}
