package main

// #include <stdlib.h>
import "C"

import (
	"strings"
	"unsafe"
)

// main is required for TinyGo to compile to Wasm.
func main() {}

//export column_args
func _args(ptr, size uint32) (ptrSize uint64) {
	eventRaw := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), int(size))
	a := args(eventRaw)
	ptr, size = stringToLeakedPtr(a)
	return (uint64(ptr) << uint64(32)) | uint64(size)
}

func args(event []byte) string {
	argsArray := []string{}
	buf := []byte{}

	// args is located at offet 57 in the raw trace event.
	// TODO: This should be calculated from the structure of the trace event.
	for _, c := range event[57:] {
		if c == 0 {
			if len(buf) == 0 {
				continue
			}

			argsArray = append(argsArray, string(buf))
			buf = []byte{}
		} else {
			buf = append(buf, c)
		}
	}

	return strings.Join(argsArray, " ")
}

// ptrToString returns a string from WebAssembly compatible numeric types
// representing its pointer and length.
func ptrToString(ptr uint32, size uint32) string {
	return unsafe.String((*byte)(unsafe.Pointer(uintptr(ptr))), size)
}

// stringToPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The returned pointer aliases the string hence the string must be kept alive
// until ptr is no longer needed.
func stringToPtr(s string) (uint32, uint32) {
	ptr := unsafe.Pointer(unsafe.StringData(s))
	return uint32(uintptr(ptr)), uint32(len(s))
}

// stringToLeakedPtr returns a pointer and size pair for the given string in a way
// compatible with WebAssembly numeric types.
// The pointer is not automatically managed by TinyGo hence it must be freed by the host.
func stringToLeakedPtr(s string) (uint32, uint32) {
	size := C.ulong(len(s))
	ptr := unsafe.Pointer(C.malloc(size))
	copy(unsafe.Slice((*byte)(ptr), size), s)
	return uint32(uintptr(ptr)), uint32(size)
}
