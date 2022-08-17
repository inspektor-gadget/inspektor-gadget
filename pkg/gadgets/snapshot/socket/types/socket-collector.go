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

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
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

	Protocol      string `json:"protocol"`
	LocalAddress  string `json:"local_address"`
	LocalPort     uint16 `json:"local_port"`
	RemoteAddress string `json:"remote_address"`
	RemotePort    uint16 `json:"remote_port"`
	Status        string `json:"status"`
	InodeNumber   uint64 `json:"inode_number"`
}

func ParseProtocol(protocol string) (Proto, error) {
	if r, ok := ProtocolsMap[strings.ToLower(protocol)]; ok {
		return r, nil
	}

	return INVALID, fmt.Errorf("%q is not a valid protocol value", protocol)
}
