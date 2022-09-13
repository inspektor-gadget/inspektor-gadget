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

package types

import (
	"fmt"

	"github.com/kinvolk/inspektor-gadget/pkg/columns"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	Pid       uint32   `json:"pid,omitempty" column:"pid,width:7"`
	Ppid      uint32   `json:"ppid,omitempty" column:"ppid,width:7"`
	UID       uint32   `json:"uid,omitempty" column:"uid,width:7"`
	MountNsID uint64   `json:"mountnsid,omitempty" column:"mntns,width:12,hide"`
	Retval    int      `json:"ret,omitempty" column:"ret,width:4"`
	Comm      string   `json:"pcomm,omitempty" column:"comm,width:16"`
	Args      []string `json:"args,omitempty" column:"args,width:24"`
}

// execColumns is defined as global variable so that the callers panic if they
// are importing this package with invalid column tags. However, force callers
// to use MustGetColumns to include additional configuration to the columns.
var execColumns = columns.MustCreateColumns[Event]()

func MustGetColumns() *columns.Columns[Event] {
	err := execColumns.SetExtractor("args", func(event *Event) (ret string) {
		for _, arg := range event.Args {
			ret += arg + " "
		}
		return ret
	})
	if err != nil {
		panic(fmt.Errorf(`setting extractor for "args" column of exec event: %w`, err))
	}
	return execColumns
}

func Base(ev eventtypes.Event) Event {
	return Event{
		Event: ev,
	}
}

func (e Event) GetBaseEvent() eventtypes.Event {
	return e.Event
}
