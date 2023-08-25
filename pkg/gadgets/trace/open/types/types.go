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
	"io/fs"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event
	eventtypes.WithMountNsID
	eventtypes.WithCgroupID

	Pid      uint32      `json:"pid,omitempty" column:"pid,minWidth:7"`
	Uid      uint32      `json:"uid,omitempty" column:"uid,minWidth:10,hide"`
	Gid      uint32      `json:"gid" column:"gid,template:gid,hide"`
	Comm     string      `json:"comm,omitempty" column:"comm,maxWidth:16"`
	Fd       int         `json:"fd,omitempty" column:"fd,minWidth:2,width:3"`
	Ret      int         `json:"ret,omitempty" column:"ret,width:3,fixed,hide"`
	Err      int         `json:"err,omitempty" column:"err,width:3,fixed"`
	Flags    []string    `json:"flags,omitempty" column:"flags,width:24,hide"`
	FlagsRaw int32       `json:"flagsRaw,omitempty"`
	Mode     string      `json:"mode,omitempty" column:"mode,width:10,hide"`
	ModeRaw  fs.FileMode `json:"modeRaw,omitempty"`
	Path     string      `json:"path,omitempty" column:"path,minWidth:24,width:32"`
	FullPath string      `json:"fullPath,omitempty" column:"fullPath,minWidth:24,width:32" columnTags:"param:full-path"`
}

func GetColumns() *columns.Columns[Event] {
	return columns.MustCreateColumns[Event]()
}

func Base(ev eventtypes.Event) *Event {
	return &Event{
		Event: ev,
	}
}
