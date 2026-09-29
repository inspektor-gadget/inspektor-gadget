// Copyright 2024 The Inspektor Gadget authors
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

package tcpbits

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTCPState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		description string
		state       uint8
		expected    string
	}{
		{
			description: "ESTABLISHED",
			state:       1,
			expected:    "ESTABLISHED",
		},
		{
			description: "SYN_SENT",
			state:       2,
			expected:    "SYN_SENT",
		},
		{
			description: "SYN_RECV",
			state:       3,
			expected:    "SYN_RECV",
		},
		{
			description: "FIN_WAIT1",
			state:       4,
			expected:    "FIN_WAIT1",
		},
		{
			description: "FIN_WAIT2",
			state:       5,
			expected:    "FIN_WAIT2",
		},
		{
			description: "TIME_WAIT",
			state:       6,
			expected:    "TIME_WAIT",
		},
		{
			description: "CLOSE",
			state:       7,
			expected:    "CLOSE",
		},
		{
			description: "CLOSE_WAIT",
			state:       8,
			expected:    "CLOSE_WAIT",
		},
		{
			description: "LAST_ACK",
			state:       9,
			expected:    "LAST_ACK",
		},
		{
			description: "LISTEN",
			state:       10,
			expected:    "LISTEN",
		},
		{
			description: "CLOSING",
			state:       11,
			expected:    "CLOSING",
		},
		{
			description: "NEW_SYN_RECV",
			state:       12,
			expected:    "NEW_SYN_RECV",
		},
		{
			description: "unknown state returns formatted string",
			state:       0,
			expected:    "UNKNOWN#0",
		},
		{
			description: "unknown high state returns formatted string",
			state:       255,
			expected:    "UNKNOWN#255",
		},
		{
			description: "unknown state 13 returns formatted string",
			state:       13,
			expected:    "UNKNOWN#13",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()
			got := TCPState(test.state)
			require.Equal(t, test.expected, got)
		})
	}
}

func TestTCPFlags(t *testing.T) {
	t.Parallel()

	tests := []struct {
		description string
		flags       uint8
		expected    string
	}{
		{
			description: "no flags set returns empty string",
			flags:       0x00,
			expected:    "",
		},
		{
			description: "FIN flag only",
			flags:       0x01,
			expected:    "FIN",
		},
		{
			description: "SYN flag only",
			flags:       0x02,
			expected:    "SYN",
		},
		{
			description: "RST flag only",
			flags:       0x04,
			expected:    "RST",
		},
		{
			description: "PSH flag only",
			flags:       0x08,
			expected:    "PSH",
		},
		{
			description: "ACK flag only",
			flags:       0x10,
			expected:    "ACK",
		},
		{
			description: "URG flag only",
			flags:       0x20,
			expected:    "URG",
		},
		{
			description: "ECE flag only",
			flags:       0x40,
			expected:    "ECE",
		},
		{
			description: "CWR flag only",
			flags:       0x80,
			expected:    "CWR",
		},
		{
			description: "SYN+ACK combination (typical server response)",
			flags:       0x12,
			expected:    "SYN|ACK",
		},
		{
			description: "FIN+ACK combination (graceful close)",
			flags:       0x11,
			expected:    "FIN|ACK",
		},
		{
			description: "PSH+ACK combination (data with acknowledgment)",
			flags:       0x18,
			expected:    "PSH|ACK",
		},
		{
			description: "RST+ACK combination",
			flags:       0x14,
			expected:    "RST|ACK",
		},
		{
			description: "all flags set returns all names in order",
			flags:       0xFF,
			expected:    "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()
			got := TCPFlags(test.flags)
			require.Equal(t, test.expected, got)
		})
	}
}
