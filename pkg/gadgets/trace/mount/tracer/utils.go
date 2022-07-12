// Copyright 2022 The Inspektor Gadget authors
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

var flagNames = []string{
	"MS_RDONLY",
	"MS_NOSUID",
	"MS_NODEV",
	"MS_NOEXEC",
	"MS_SYNCHRONOUS",
	"MS_REMOUNT",
	"MS_MANDLOCK",
	"MS_DIRSYNC",
	"MS_NOSYMFOLLOW",
	"MS_NOATIME",
	"MS_NODIRATIME",
	"MS_BIND",
	"MS_MOVE",
	"MS_REC",
	"MS_VERBOSE",
	"MS_SILENT",
	"MS_POSIXACL",
	"MS_UNBINDABLE",
	"MS_PRIVATE",
	"MS_SLAVE",
	"MS_SHARED",
	"MS_RELATIME",
	"MS_KERNMOUNT",
	"MS_I_VERSION",
	"MS_STRICTATIME",
	"MS_LAZYTIME",
	"MS_SUBMOUNT",
	"MS_NOREMOTELOCK",
	"MS_NOSEC",
	"MS_BORN",
	"MS_ACTIVE",
	"MS_NOUSER",
}

func DecodeFlags(flags uint64) []string {
	flagsStr := []string{}

	for i, val := range flagNames {
		if (1<<i)&flags == 0 {
			continue
		}
		flagsStr = append(flagsStr, val)
	}

	return flagsStr
}
