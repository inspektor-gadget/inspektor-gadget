package uprobetracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unsafe"
)

func readFromBytes[T any](obj *T, rawData []byte) error {
	if int(unsafe.Sizeof(*obj)) != len(rawData) {
		return errors.New("reading from bytes: length mismatched")
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
