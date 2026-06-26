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

import (
	"fmt"
	"strings"
)

// Decode turns a SELinux access-vector bitmask into a human-readable
// "{ perm1 perm2 }" string using the permission ordering of the given target
// class, mirroring how permissions appear in the kernel audit log. An empty
// mask yields an empty string. Bits that don't map to a known permission (e.g.
// a newer kernel, or an unknown class) are rendered as their hexadecimal value
// so no information is lost.
func Decode(tclass string, mask uint32) string {
	if mask == 0 {
		return ""
	}

	perms := ClassPerms[tclass]
	set := make([]string, 0, 4)
	for i := 0; i < 32; i++ {
		bit := uint32(1) << uint(i)
		if mask&bit == 0 {
			continue
		}
		if i < len(perms) {
			set = append(set, perms[i])
		} else {
			set = append(set, fmt.Sprintf("0x%x", bit))
		}
	}

	return "{ " + strings.Join(set, " ") + " }"
}
