package uprobetracer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

const (
	cache1Header    string = "ld.so-1.7.0"
	cache1HeaderLen int    = 11

	cache2Header    string = "glibc-ld.so.cache"
	cache2HeaderLen int    = 17
	cache2Version   string = "1.1"

	ldCache1EntrySize uint32 = 12
	ldCache1Size      uint32 = 16
	ldCache2EntrySize uint32 = 24
	ldCache2Size      uint32 = 48
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

type ldEntry struct {
	Key   string
	Value string
}

func readFromBytes[T any](obj *T, rawData []byte) error {
	if int(unsafe.Sizeof(*obj)) != len(rawData) {
		return fmt.Errorf("reading from bytes: length mismatched")
	}
	buffer := bytes.NewBuffer(rawData)
	err := binary.Read(buffer, binary.NativeEndian, obj)
	if err != nil {
		return err
	}
	return nil
}

func readStringFromBytes(data []byte, startPos uint32) string {
	res := ""
	for i := startPos; i < uint32(len(data)); i++ {
		if data[i] == 0 {
			return res
		}
		res += string(data[i])
	}
	return ""
}

func readCacheFormat1(data []byte) []ldEntry {
	var ldEntries []ldEntry

	ldCache := ldCache1{}
	if uint32(len(data)) <= ldCache1Size {
		return nil
	}
	err := readFromBytes(&ldCache, data[:ldCache1Size])
	if err != nil {
		return nil
	}
	ldEntriesOffset := ldCache1Size
	ldStringsOffset := ldCache1Size + ldCache1EntrySize*ldCache.EntryCount
	for i := uint32(0); i < ldCache.EntryCount; i++ {
		entryOffset := ldEntriesOffset + i*ldCache1EntrySize
		entry := ldCache1Entry{}
		if uint32(len(data)) <= entryOffset+ldCache1EntrySize {
			return nil
		}
		err := readFromBytes(&entry, data[entryOffset:entryOffset+ldCache1EntrySize])
		if err != nil {
			return nil
		}
		keyOffset := ldStringsOffset + entry.Key
		valueOffset := ldStringsOffset + entry.Value
		key := readStringFromBytes(data, keyOffset)
		value := readStringFromBytes(data, valueOffset)
		ldEntries = append(ldEntries, ldEntry{key, value})
	}
	return ldEntries
}

func readCacheFormat2(data []byte) []ldEntry {
	var ldEntries []ldEntry

	if !bytes.Equal([]byte(cache2Header), data[:cache2HeaderLen]) {
		return nil
	}
	ldCache := ldCache2{}
	if uint32(len(data)) <= ldCache2Size {
		return nil
	}
	err := readFromBytes(&ldCache, data[:ldCache2Size])
	if err != nil {
		return nil
	}
	ldEntriesOffset := ldCache2Size
	for i := uint32(0); i < ldCache.EntryCount; i++ {
		entryOffset := ldEntriesOffset + i*ldCache2EntrySize
		entry := ldCache2Entry{}
		if uint32(len(data)) <= entryOffset+ldCache2EntrySize {
			return nil
		}
		err := readFromBytes(&entry, data[entryOffset:entryOffset+ldCache2EntrySize])
		if err != nil {
			return nil
		}
		keyOffset := entry.Key
		valueOffset := entry.Value
		key := readStringFromBytes(data, keyOffset)
		value := readStringFromBytes(data, valueOffset)
		ldEntries = append(ldEntries, ldEntry{key, value})
	}
	return ldEntries
}

// simulate the loader's behaviour, find library path in containers' `/etc/ld.so.cache`.
// see https://github.com/bminor/glibc/blob/master/elf/cache.c#L292, the `print_cache` func
// see https://github.com/iovisor/bcc/blob/master/src/cc/bcc_proc.c#L508, the `bcc_procutils_which_so` func
func parseLdCache(ldCachePath string, libraryName string) []string {
	fileInfo, err := os.Stat(ldCachePath)
	if err != nil {
		return nil
	}
	if fileInfo.Mode()&os.ModeNamedPipe != 0 {
		return nil
	}
	ldCacheFile, err := os.ReadFile(ldCachePath)
	if err != nil {
		return nil
	}
	ldCacheFileSize := uint32(len(ldCacheFile))

	var ldEntries []ldEntry
	var filteredLibraries []string

	if bytes.Equal([]byte(cache1Header), ldCacheFile[:cache1HeaderLen]) {
		cache1 := ldCache1{}
		if uint32(len(ldCacheFile)) <= ldCache1Size {
			return nil
		}
		err := readFromBytes(&cache1, ldCacheFile[:ldCache1Size])
		if err != nil {
			return nil
		}
		cache1Len := ldCache1Size + cache1.EntryCount*ldCache1EntrySize
		cache1Len = (cache1Len + 7) / 8 * 8
		if ldCacheFileSize > (cache1Len + ldCache2Size) {
			ldEntries = readCacheFormat2(ldCacheFile)
		} else {
			ldEntries = readCacheFormat1(ldCacheFile)
		}
	} else {
		ldEntries = readCacheFormat2(ldCacheFile)
	}

	if ldEntries == nil {
		return nil
	}

	// filter library entries with given library name
	for _, entry := range ldEntries {
		if strings.HasPrefix(entry.Key, libraryName+".so") {
			filteredLibraries = append(filteredLibraries, entry.Value)
		}
	}

	return filteredLibraries
}
