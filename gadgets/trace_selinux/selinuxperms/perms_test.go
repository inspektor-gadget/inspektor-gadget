// Copyright 2026 The Inspektor Gadget authors
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

package selinuxperms

import "testing"

func TestDecode(t *testing.T) {
	tests := []struct {
		name   string
		tclass string
		mask   uint32
		want   string
	}{
		{
			name:   "empty mask",
			tclass: "file",
			mask:   0,
			want:   "",
		},
		{
			// 1<<26 on the file class. This is the value observed for a
			// container_t domain denied executing an unlabeled file.
			name:   "file execute_no_trans",
			tclass: "file",
			mask:   67108864,
			want:   "{ execute_no_trans }",
		},
		{
			// read (1<<1) | open (1<<18) = 2 + 262144 = 262146
			name:   "file read+open",
			tclass: "file",
			mask:   262146,
			want:   "{ read open }",
		},
		{
			// name_connect (1<<22) on tcp_socket.
			name:   "tcp_socket name_connect",
			tclass: "tcp_socket",
			mask:   1 << 22,
			want:   "{ name_connect }",
		},
		{
			name:   "unknown class falls back to hex",
			tclass: "does_not_exist",
			mask:   1 << 3,
			want:   "{ 0x8 }",
		},
		{
			// Bit beyond the known perms for the class falls back to hex.
			name:   "unknown bit falls back to hex",
			tclass: "fd", // only "use" (1<<0)
			mask:   1 << 5,
			want:   "{ 0x20 }",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decode(tt.tclass, tt.mask)
			if got != tt.want {
				t.Errorf("Decode(%q, %d) = %q, want %q", tt.tclass, tt.mask, got, tt.want)
			}
		})
	}
}

func TestDecodeBoundaries(t *testing.T) {
	tests := []struct {
		name, class string
		mask        uint32
		want        string
	}{
		{"empty", "file", 0, ""},
		{"unknown class preserves bits", "future_class", 0x80000001, "{ 0x1 0x80000000 }"},
		{"known and unknown bit", "fd", 0x80000001, "{ use 0x80000000 }"},
		{"file read write", "file", 0x6, "{ read write }"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Decode(tt.class, tt.mask); got != tt.want {
				t.Fatalf("Decode(%q, %#x) = %q, want %q", tt.class, tt.mask, got, tt.want)
			}
		})
	}
}

func FuzzDecodeNeverDropsSetBits(f *testing.F) {
	f.Add("file", uint32(0xffffffff))
	f.Add("unknown", uint32(0x80000001))
	f.Fuzz(func(t *testing.T, class string, mask uint32) {
		got := Decode(class, mask)
		if mask == 0 && got != "" {
			t.Fatalf("zero mask: %q", got)
		}
		if mask != 0 && (len(got) < 4 || got[:2] != "{ " || got[len(got)-2:] != " }") {
			t.Fatalf("malformed result %q", got)
		}
	})
}
