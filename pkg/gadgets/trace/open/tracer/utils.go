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

var flagNames = []string{
	"O_CREAT",
	"O_EXCL",
	"O_NOCTTY",
	"O_TRUNC",
	"O_APPEND",
	"O_NONBLOCK",
	"O_DSYNC",
	"O_FASYNC",
	"O_DIRECT",
	"O_LARGEFILE",
	"O_DIRECTORY",
	"O_NOFOLLOW",
	"O_NOATIME",
	"O_CLOEXEC",
}

func DecodeFlags(flags int32) []string {
	flagsStr := []string{}

	// We first need to deal with the first 3 bits which indicates access mode.
	switch flags & 0b11 {
	case 0:
		flagsStr = append(flagsStr, "O_RDONLY")
	case 1:
		flagsStr = append(flagsStr, "O_WRONLY")
	case 2:
		flagsStr = append(flagsStr, "O_RDWR")
	}

	// Then, we need to remove the last 6 bits and we can deal with the other
	// flags.
	// Indeed, O_CREAT is defined as 00000100, see:
	// https://github.com/torvalds/linux/blob/9d646009f65d/include/uapi/asm-generic/fcntl.h#L24
	flags >>= 6
	for i, val := range flagNames {
		if (1<<i)&flags == 0 {
			continue
		}
		flagsStr = append(flagsStr, val)
	}

	return flagsStr
}
