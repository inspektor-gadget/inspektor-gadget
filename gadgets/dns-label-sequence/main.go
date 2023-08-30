package main

import (
	"unsafe"
)

var bufIn [1024]byte
var bufOut [1024]byte

//go:export alloc
func alloc(size uint32) *byte {
	return &bufIn[0]
}

//go:export parseLabelSequence
func parseLabelSequence(input *byte, inputLength int) uint64 {
	inputSlice := make([]byte, inputLength)
	for i := 0; i < inputLength; i++ {
		inputSlice[i] = *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(input)) + uintptr(i)))
	}
	var str string
	for i := 0; i < inputLength; i++ {
		length := int(inputSlice[i])
		if length == 0 {
			break
		}
		if i+1+length < inputLength {
			str += string(inputSlice[i+1:i+1+length]) + "."
		}
		i += length
	}

	copy(bufOut[:], str)

	return (uint64(uintptr(unsafe.Pointer(&bufOut[0]))) << uint64(32)) | uint64(len(str))
}

// main is required for the `wasi` target, even if it isn't used.
// See https://wazero.io/languages/tinygo/#why-do-i-have-to-define-main
func main() {}
