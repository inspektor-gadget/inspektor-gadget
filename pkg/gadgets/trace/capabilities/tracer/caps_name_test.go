// Copyright 2023 The Inspektor Gadget authors
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

package tracer

import (
	"reflect"
	"testing"
)

func TestCapsNames(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		bitfield uint64
		expected []string
	}

	for name, test := range map[string]testDefinition{
		"empty": {
			bitfield: 0,
			expected: []string{},
		},
		"all": {
			bitfield: 0x3FFFFFFFFF,
			expected: []string{
				"chown",
				"dac_override",
				"dac_read_search",
				"fowner",
				"fsetid",
				"kill",
				"setgid",
				"setuid",
				"setpcap",
				"linux_immutable",
				"net_bind_service",
				"net_broadcast",
				"net_admin",
				"net_raw",
				"ipc_lock",
				"ipc_owner",
				"sys_module",
				"sys_rawio",
				"sys_chroot",
				"sys_ptrace",
				"sys_pacct",
				"sys_admin",
				"sys_boot",
				"sys_nice",
				"sys_resource",
				"sys_time",
				"sys_tty_config",
				"mknod",
				"lease",
				"audit_write",
				"audit_control",
				"setfcap",
				"mac_override",
				"mac_admin",
				"syslog",
				"wake_alarm",
				"block_suspend",
				"audit_read",
			},
		},
		"two_caps": {
			bitfield: 0x240000,
			expected: []string{
				"sys_chroot",
				"sys_admin",
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ret := capsNames(test.bitfield)
			if !reflect.DeepEqual(ret, test.expected) {
				t.Fatalf("expected %q (#%d), found %q (#%d)",
					test.expected,
					len(test.expected),
					ret,
					len(ret),
				)
			}
		})
	}
}
