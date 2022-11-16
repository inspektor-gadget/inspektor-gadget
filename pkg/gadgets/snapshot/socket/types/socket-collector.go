// Copyright 2021 The Inspektor Gadget authors
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
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Proto int

const (
	INVALID Proto = iota
	ALL
	TCP
	UDP
)

var ProtocolsMap = map[string]Proto{
	"all": ALL,
	"tcp": TCP,
	"udp": UDP,
}

type Event struct {
	eventtypes.Event

	Protocol      string `json:"protocol" column:"protocol,maxWidth:8"`
	LocalAddress  string `json:"localAddress" column:"localAddr,template:ipaddr,hide"`
	LocalPort     uint16 `json:"localPort" column:"localPort,template:ipport,hide"`
	RemoteAddress string `json:"remoteAddress" column:"remoteAddr,template:ipaddr,hide"`
	RemotePort    uint16 `json:"remotePort" column:"remotePort,template:ipport,hide"`
	Status        string `json:"status" column:"status,order:1002,maxWidth:12"`
	InodeNumber   uint64 `json:"inodeNumber" column:"inode,hide"`
}

func GetColumns() *columns.Columns[Event] {
	cols := columns.MustCreateColumns[Event]()

	col, _ := cols.GetColumn("container")
	col.Visible = false

	cols.MustAddColumn(columns.Column[Event]{
		Name:     "local",
		MinWidth: 21, // 15(ipv4) + 1(:) + 5(port)
		MaxWidth: 51, // 45(ipv4 mapped ipv6) + 1(:) + 5(port)
		Visible:  true,
		Order:    1000,
		Extractor: func(e *Event) string {
			return fmt.Sprintf("%s:%d", e.LocalAddress, e.LocalPort)
		},
	})

	cols.MustAddColumn(columns.Column[Event]{
		Name:     "remote",
		MinWidth: 21, // 15(ipv4) + 1(:) + 5(port)
		MaxWidth: 51, // 45(ipv4 mapped ipv6) + 1(:) + 5(port)
		Visible:  true,
		Order:    1001,
		Extractor: func(e *Event) string {
			return fmt.Sprintf("%s:%d", e.RemoteAddress, e.RemotePort)
		},
	})

	return cols
}

func ParseProtocol(protocol string) (Proto, error) {
	if r, ok := ProtocolsMap[strings.ToLower(protocol)]; ok {
		return r, nil
	}

	return INVALID, fmt.Errorf("%q is not a valid protocol value", protocol)
}
