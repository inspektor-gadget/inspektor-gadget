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

package main

import (
	"io/fs"
	"math/bits"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Standard Linux file open flags from <fcntl.h>
const (
	// Access modes (handled separately)
	O_RDONLY  = 0
	O_WRONLY  = 1
	O_RDWR    = 2
	O_ACCMODE = 3

	// Bit flags
	O_CREAT     = 0100
	O_EXCL      = 0200
	O_NOCTTY    = 0400
	O_TRUNC     = 01000
	O_APPEND    = 02000
	O_NONBLOCK  = 04000
	O_DSYNC     = 010000
	O_FASYNC    = 020000
	O_DIRECT    = 040000
	O_LARGEFILE = 0100000
	O_DIRECTORY = 0200000
	O_NOFOLLOW  = 0400000
	O_NOATIME   = 01000000
	O_CLOEXEC   = 02000000
)

// flagMap pairs the bitmask of a flag with its string representation.
// Using a slice of structs makes the relationship explicit and order-independent.
var flagMap = []struct {
	val  int32
	name string
}{
	{O_CREAT, "O_CREAT"},
	{O_EXCL, "O_EXCL"},
	{O_NOCTTY, "O_NOCTTY"},
	{O_TRUNC, "O_TRUNC"},
	{O_APPEND, "O_APPEND"},
	{O_NONBLOCK, "O_NONBLOCK"},
	{O_DSYNC, "O_DSYNC"},
	{O_FASYNC, "O_FASYNC"},
	{O_DIRECT, "O_DIRECT"},
	{O_LARGEFILE, "O_LARGEFILE"},
	{O_DIRECTORY, "O_DIRECTORY"},
	{O_NOFOLLOW, "O_NOFOLLOW"},
	{O_NOATIME, "O_NOATIME"},
	{O_CLOEXEC, "O_CLOEXEC"},
}

func decodeFlags(flags int32) []string {
	// Pre-allocate a slice with a reasonable capacity to avoid reallocations.
	// The number of set bits gives an exact count.
	capacity := bits.OnesCount32(uint32(flags))
	out := make([]string, 0, capacity)

	// Handle the access mode, which is not a bitmask.
	switch flags & O_ACCMODE {
	case O_RDONLY:
		out = append(out, "O_RDONLY")
	case O_WRONLY:
		out = append(out, "O_WRONLY")
	case O_RDWR:
		out = append(out, "O_RDWR")
	}

	// Check each flag by its actual value.
	for _, f := range flagMap {
		if (flags & f.val) == f.val {
			out = append(out, f.name)
		}
	}

	return out
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Errorf("failed to get datasource: %s", err)
		return 1
	}

	modeRawF, err := ds.GetField("mode_raw")
	if err != nil {
		api.Errorf("failed to get field: %s", err)
		return 1
	}

	// TODO: add attributes / annotations
	modeF, err := ds.AddField("mode", api.Kind_String)
	if err != nil {
		api.Errorf("failed to add field: %s", err)
		return 1
	}

	flagsRawF, err := ds.GetField("flags_raw")
	if err != nil {
		api.Errorf("failed to get field: %s", err)
		return 1
	}

	// TODO: add attributes / annotations
	flagsF, err := ds.AddField("flags", api.Kind_String)
	if err != nil {
		api.Errorf("failed to add field: %s", err)
		return 1
	}

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// mode
		modeRaw, err := modeRawF.Uint16(data)
		if err != nil {
			api.Warnf("failed to get mode: %s", err)
			return
		}
		modeStr := fs.FileMode(modeRaw)
		modeF.SetString(data, modeStr.String())

		// flags
		flagsRaw, err := flagsRawF.Int32(data)
		if err != nil {
			api.Warnf("failed to get flags: %s", err)
			return
		}

		flagsStr := decodeFlags(flagsRaw)
		// TODO: the datasource doesn't support arrays yet.
		flagsF.SetString(data, strings.Join(flagsStr, "|"))

	}, 0)

	return 0
}

func main() {}
