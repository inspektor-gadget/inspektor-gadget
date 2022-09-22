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

package types

import (
	"encoding/json"
	"fmt"
)

type EventType string

var node string

func Init(nodeName string) {
	node = nodeName
}

type CommonData struct {
	// Node where the event comes from
	Node string `json:"node,omitempty" column:"node,width:30,ellipsis:middle" columnTags:"kubernetes"`

	// Pod namespace where the event comes from, or empty for host-level
	// event
	Namespace string `json:"namespace,omitempty" column:"namespace,width:30" columnTags:"kubernetes"`

	// Pod where the event comes from, or empty for host-level event
	Pod string `json:"pod,omitempty" column:"pod,width:30,ellipsis:middle" columnTags:"kubernetes"`

	// Container where the event comes from, or empty for host-level or
	// pod-level event
	Container string `json:"container,omitempty" column:"container,width:30" columnTags:"kubernetes,runtime"`
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

	// Type indicates the kind of this event
	Type EventType `json:"type"`

	// Message when Type is ERR, WARN, DEBUG or INFO
	Message string `json:"message,omitempty"`
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
