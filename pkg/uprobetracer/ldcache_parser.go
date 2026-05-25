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

package uprobetracer

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/secureopen"
)

type ldCache1Entry struct {
	Flags int32
	Key   uint32
	Value uint32
}

type ldCache1 struct {
	Header     [11]int8
	EntryCount uint32
}

type ldCache2Entry struct {
	Flags int32
	Key   uint32
	Value uint32
	Pad1_ uint32
	Pad2_ uint64
}

type ldCache2 struct {
	Header         [17]int8
	Version        [3]int8
	EntryCount     uint32
	StringTableLen uint32
	Pad_           [5]uint32
}

const (
	cache1Header string = "ld.so-1.7.0"
	cache2Header string = "glibc-ld.so.cache1.1"

	ldCache1EntrySize = uint32(unsafe.Sizeof(ldCache1Entry{}))
	ldCache1Size      = uint32(unsafe.Sizeof(ldCache1{}))
	ldCache2EntrySize = uint32(unsafe.Sizeof(ldCache2Entry{}))
	ldCache2Size      = uint32(unsafe.Sizeof(ldCache2{}))

	// ld.so.cache is typically less than 200 KiB.
	// 16 MiB should be enough.
	ldCacheMaxSize = int64(16 * 1024 * 1024)

	// A real ld.so.cache has only a handful of entries per library name
	// (typically 1–3 across architecture variants). Cap results to bound
	// memory usage when parsing a crafted file.
	ldCacheMaxResults = 64
)

func readCacheFormat1(data []byte, libraryPrefix string) []string {
	var results []string

	if uint32(len(data)) <= ldCache1Size {
		return nil
	}
	ldCache := ldCache1{}
	err := reinterpretBytes(&ldCache, data[:ldCache1Size])
	if err != nil {
		return nil
	}
	ldEntriesOffset := ldCache1Size
	// Cap entry count based on actual file size to prevent excessive iteration.
	maxEntries := (uint32(len(data)) - ldEntriesOffset) / ldCache1EntrySize
	if ldCache.EntryCount > maxEntries {
		ldCache.EntryCount = maxEntries
	}
	ldStringsOffset := ldEntriesOffset + ldCache1EntrySize*ldCache.EntryCount
	for i := uint32(0); i < ldCache.EntryCount; i++ {
		entryOffset := ldEntriesOffset + i*ldCache1EntrySize
		entry := ldCache1Entry{}
		if uint32(len(data)) <= entryOffset+ldCache1EntrySize {
			return nil
		}
		err := reinterpretBytes(&entry, data[entryOffset:entryOffset+ldCache1EntrySize])
		if err != nil {
			return nil
		}
		keyOffset := ldStringsOffset + entry.Key
		if matchStringInBytes(data, keyOffset, libraryPrefix) {
			valueOffset := ldStringsOffset + entry.Value
			value := readStringFromBytes(data, valueOffset)
			results = append(results, value)
			if len(results) >= ldCacheMaxResults {
				break
			}
		}
	}
	return results
}

func readCacheFormat2(data []byte, libraryPrefix string) []string {
	var results []string

	if len(data) < len(cache2Header) {
		return nil
	}
	if !bytes.Equal([]byte(cache2Header), data[:len(cache2Header)]) {
		return nil
	}
	ldCache := ldCache2{}
	if uint32(len(data)) <= ldCache2Size {
		return nil
	}
	err := reinterpretBytes(&ldCache, data[:ldCache2Size])
	if err != nil {
		return nil
	}
	ldEntriesOffset := ldCache2Size
	// Cap entry count based on actual file size to prevent excessive iteration.
	maxEntries := (uint32(len(data)) - ldEntriesOffset) / ldCache2EntrySize
	if ldCache.EntryCount > maxEntries {
		ldCache.EntryCount = maxEntries
	}
	for i := uint32(0); i < ldCache.EntryCount; i++ {
		entryOffset := ldEntriesOffset + i*ldCache2EntrySize
		entry := ldCache2Entry{}
		if uint32(len(data)) <= entryOffset+ldCache2EntrySize {
			return nil
		}
		err := reinterpretBytes(&entry, data[entryOffset:entryOffset+ldCache2EntrySize])
		if err != nil {
			return nil
		}
		keyOffset := entry.Key
		if matchStringInBytes(data, keyOffset, libraryPrefix) {
			valueOffset := entry.Value
			value := readStringFromBytes(data, valueOffset)
			results = append(results, value)
			if len(results) >= ldCacheMaxResults {
				break
			}
		}
	}
	return results
}

// simulate the loader's behaviour, find library path in containers' `/etc/ld.so.cache`.
// see https://github.com/bminor/glibc/blob/master/elf/cache.c#L292, the `print_cache` func
// see https://github.com/iovisor/bcc/blob/master/src/cc/bcc_proc.c#L508, the `bcc_procutils_which_so` func
func parseLdCache(containerPid uint32, ldCachePath string, libraryName string) ([]string, error) {
	ldCacheFile, err := secureopen.ReadFileInContainer(containerPid, ldCachePath, ldCacheMaxSize)
	if err != nil {
		return nil, fmt.Errorf("reading file %q in container pid %d: %w", ldCachePath, containerPid, err)
	}
	ldCacheFileSize := uint32(len(ldCacheFile))

	var filteredLibraries []string
	libraryPrefix := libraryName + ".so"

	if len(ldCacheFile) >= len(cache1Header) && bytes.Equal([]byte(cache1Header), ldCacheFile[:len(cache1Header)]) {
		cache1 := ldCache1{}
		if uint32(len(ldCacheFile)) <= ldCache1Size {
			return nil, errors.New("ldCache format error")
		}
		err := reinterpretBytes(&cache1, ldCacheFile[:ldCache1Size])
		if err != nil {
			return nil, errors.New("ldCache format error")
		}
		// Use uint64 arithmetic to avoid overflow when computing the
		// cache1 section length from the untrusted EntryCount field.
		cache1Len := uint64(ldCache1Size) + uint64(cache1.EntryCount)*uint64(ldCache1EntrySize)
		cache1Len = (cache1Len + 7) / 8 * 8
		if uint64(ldCacheFileSize) > (cache1Len + uint64(ldCache2Size)) {
			filteredLibraries = readCacheFormat2(ldCacheFile, libraryPrefix)
		} else {
			filteredLibraries = readCacheFormat1(ldCacheFile, libraryPrefix)
		}
	} else {
		filteredLibraries = readCacheFormat2(ldCacheFile, libraryPrefix)
	}

	if filteredLibraries == nil {
		return nil, errors.New("ldCache format error")
	}

	return filteredLibraries, nil
}
