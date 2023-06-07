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

type RemoteKind string

const (
	RemoteKindPod     RemoteKind = "pod"
	RemoteKindService RemoteKind = "svc"
	RemoteKindOther   RemoteKind = "other"
)

type RuntimeName string

func (r RuntimeName) String() string {
	return string(r)
}

const (
	RuntimeNameDocker     RuntimeName = "docker"
	RuntimeNameContainerd RuntimeName = "containerd"
	RuntimeNameCrio       RuntimeName = "cri-o"
	RuntimeNamePodman     RuntimeName = "podman"
	RuntimeNameUnknown    RuntimeName = "unknown"
)

func String2RuntimeName(name string) RuntimeName {
	switch name {
	case string(RuntimeNameDocker):
		return RuntimeNameDocker
	case string(RuntimeNameContainerd):
		return RuntimeNameContainerd
	case string(RuntimeNameCrio):
		return RuntimeNameCrio
	case string(RuntimeNamePodman):
		return RuntimeNamePodman
	}
	return RuntimeNameUnknown
}

type BasicRuntimeMetadata struct {
	// Runtime is the name of the container runtime. It is useful to distinguish
	// who is the "owner" of each container in a list of containers collected
	// from multiples runtimes.
	Runtime RuntimeName `json:"runtime,omitempty" column:"runtime,minWidth:5,maxWidth:12"`

	// ContainerID is the container ContainerID without the container runtime prefix. For
	// instance, without the "cri-o://" for CRI-O.
	ContainerID string `json:"containerId,omitempty" column:"containerid,width:13,maxWidth:64"`

	// Container is the container name. In the case the container runtime
	// response with multiples, Container contains only the first element.
	Container string `json:"container,omitempty" column:"container,template:container"`
}

func (b *BasicRuntimeMetadata) IsEnriched() bool {
	return b.Runtime != RuntimeNameUnknown && b.Runtime != "" && b.ContainerID != "" && b.Container != ""
}

type BasicK8sMetadata struct {
	Namespace string `json:"namespace,omitempty" column:"namespace,template:namespace"`
	Pod       string `json:"pod,omitempty" column:"pod,template:pod"`
	Container string `json:"container,omitempty" column:"container,template:container"`
}

func (b *BasicK8sMetadata) IsEnriched() bool {
	return b.Namespace != "" && b.Pod != "" && b.Container != ""
}

type K8sMetadata struct {
	Node string `json:"node,omitempty" column:"node,template:node"`

	BasicK8sMetadata `json:",inline"`

	// HostNetwork is true if the container uses the host network namespace
	HostNetwork bool `json:"hostNetwork,omitempty" column:"hostnetwork,hide"`
}

type CommonData struct {
	// Runtime contains the container runtime metadata of the container
	// that generated the event
	Runtime BasicRuntimeMetadata `json:"runtime,omitempty" column:"runtime" columnTags:"runtime"`

	// K8s contains the Kubernetes metadata of the object that generated the
	// event
	K8s K8sMetadata `json:"k8s,omitempty" columnTags:"kubernetes"`
}

func (c *CommonData) SetNode(node string) {
	c.K8s.Node = node
}

func (c *CommonData) SetContainerMetadata(k8s *BasicK8sMetadata, runtime *BasicRuntimeMetadata, setContainerName bool) {
	c.K8s.Pod = k8s.Pod
	c.K8s.Namespace = k8s.Namespace

	// In some cases, we don't have enough information to determine the exact
	// container where the event happened.
	if setContainerName {
		c.K8s.Container = k8s.Container

		c.Runtime.Runtime = runtime.Runtime
		c.Runtime.Container = runtime.Container
		c.Runtime.ContainerID = runtime.ContainerID
	}
}

func (c *CommonData) GetNode() string {
	return c.K8s.Node
}

func (c *CommonData) GetPod() string {
	return c.K8s.Pod
}

func (c *CommonData) GetNamespace() string {
	return c.K8s.Namespace
}

func (c *CommonData) GetContainer() string {
	return c.K8s.Container
}

type EndpointDetails struct {
	Namespace string
	Name      string
	Kind      RemoteKind
	PodLabels map[string]string
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
