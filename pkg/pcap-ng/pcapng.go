// Copyright 2025 The Inspektor Gadget authors
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

// Package pcapng provides a thread-safe writer for the pcap-ng file format.
//
// The pcap-ng (PCAP Next Generation) format is a flexible, extensible successor to the
// classic pcap format, allowing for more metadata to be stored alongside packet data.
//
// Example usage:
//
//	// Create a new pcap-ng writer
//	writer, err := pcapng.New(outputFile)
//	if err != nil {
//		log.Fatalf("Failed to create pcap-ng writer: %v", err)
//	}
//
//	// Add a comment to the section header (must be done before writing packets)
//	writer.SetSectionComment("Capture session started at 2023-01-01")
//
//	// Write a packet with default options
//	err = writer.WritePacket(packetData, nil)
//	if err != nil {
//		log.Fatalf("Failed to write packet: %v", err)
//	}
//
//	// Write a packet with custom options including a comment
//	opts := &pcapng.PacketOptions{
//		Timestamp:      captureTime,
//		InterfaceIndex: ifIndex,
//		Comment:        "Interesting packet with unusual flags",
//	}
//	err = writer.WritePacket(packetData, opts)
//	if err != nil {
//		log.Fatalf("Failed to write packet: %v", err)
//	}
//
//	// Ensure all data is written
//	err = writer.Flush()
//	if err != nil {
//		log.Fatalf("Failed to flush data: %v", err)
//	}
//
//	// Close the writer when done
//	err = writer.Close()
//	if err != nil {
//		log.Fatalf("Failed to close writer: %v", err)
//	}
package pcapng

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
)

// LinkType represents the type of link layer in the packet data.
type LinkType uint16

// Common link types
const (
	LinkTypeNull      LinkType = 0
	LinkTypeEthernet  LinkType = 1
	LinkTypeWifi      LinkType = 105
	LinkTypeLinuxSLL  LinkType = 113
	LinkTypeLinuxSLL2 LinkType = 276
	LinkTypeRaw       LinkType = 101
	LinkTypeLoop      LinkType = 108
	LinkTypeUSB       LinkType = 186
	LinkTypeBluetooth LinkType = 201
	LinkTypeNetlink   LinkType = 253
	LinkTypeIPv4      LinkType = 228
	LinkTypeIPv6      LinkType = 229
)

// Block types
const (
	blockTypeInterfaceDescription uint32 = 0x00000001
	blockTypePacket               uint32 = 0x00000002
	blockTypeSimplePacket         uint32 = 0x00000003
	blockTypeNameResolution       uint32 = 0x00000004
	blockTypeInterfaceStatistics  uint32 = 0x00000005
	blockTypeEnhancedPacket       uint32 = 0x00000006
	blockTypeSectionHeader        uint32 = 0x0A0D0D0A
)

// Option types
const (
	optEndOfOpts    uint16 = 0
	optComment      uint16 = 1
	optCustomBinary uint16 = 2989 // Example custom option
)

// Interface description block options
const (
	ifOptName        uint16 = 2
	ifOptDescription uint16 = 3
	ifOptIPv4Addr    uint16 = 4
	ifOptIPv6Addr    uint16 = 5
	ifOptMACAddr     uint16 = 6
	ifOptEUIAddr     uint16 = 7
	ifOptSpeed       uint16 = 8
	ifOptTSResol     uint16 = 9
	ifOptTZone       uint16 = 10
	ifOptFilter      uint16 = 11
	ifOptOS          uint16 = 12
	ifOptFCSLen      uint16 = 13
	ifOptTSOffset    uint16 = 14
)

// Enhanced packet block options
const (
	epbOptFlags       uint16 = 2
	epbOptHash        uint16 = 3
	epbOptDropCount   uint16 = 4
	epbOptPacketID    uint16 = 5
	epbOptQueue       uint16 = 6
	epbOptVerdictTime uint16 = 7
)

// Magic number for section header block
var magicNumber = []byte{0x4d, 0x3c, 0x2b, 0x1a} //  []byte{0x1A, 0x2B, 0x3C, 0x4D}

// Writer is a thread-safe pcap-ng writer that minimizes allocations.
type Writer struct {
	w              io.Writer
	mu             sync.Mutex
	buf            []byte
	sectionWritten bool
	interfaces     []interfaceInfo
	sectionComment string
}

type interfaceInfo struct {
	linkType LinkType
	snapLen  uint32
}

// PacketOptions contains options for writing a packet.
type PacketOptions struct {
	// Timestamp is the timestamp of the packet. If zero, current time is used.
	Timestamp time.Time
	// InterfaceIndex is the index of the interface the packet was captured on.
	InterfaceIndex int
	// CaptureLength is the number of bytes captured. If zero, the length of the payload is used.
	CaptureLength int
	// Length is the original length of the packet. If zero, the length of the payload is used.
	Length int
	// AncillaryData is additional data to be stored with the packet.
	AncillaryData []interface{}
	// Comment is an optional comment to be stored with the packet.
	Comment string
}

// New creates a new pcap-ng writer.
func New(w io.Writer) (*Writer, error) {
	return NewWithLinkType(w, LinkTypeEthernet)
}

// NewWithLinkType creates a new pcap-ng writer with the specified link type.
func NewWithLinkType(w io.Writer, linkType LinkType) (*Writer, error) {
	writer := &Writer{
		w:          w,
		buf:        make([]byte, 65536), // 64KB buffer for writing blocks
		interfaces: []interfaceInfo{{linkType: linkType, snapLen: 65535}},
	}

	// Write section header block
	if err := writer.writeSectionHeader(); err != nil {
		return nil, fmt.Errorf("writing section header: %w", err)
	}

	// Write interface description block
	if err := writer.writeInterfaceDescription(0); err != nil {
		return nil, fmt.Errorf("writing interface description: %w", err)
	}

	return writer, nil
}

// WritePacket writes a packet to the pcap-ng file.
func (w *Writer) WritePacket(payload []byte, opts *PacketOptions) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Use default options if none provided
	if opts == nil {
		opts = &PacketOptions{}
	}

	// Use current time if timestamp is zero
	timestamp := opts.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Use payload length if capture length or length is zero
	payloadLen := len(payload)
	captureLength := opts.CaptureLength
	if captureLength == 0 {
		captureLength = payloadLen
	}
	length := opts.Length
	if length == 0 {
		length = payloadLen
	}

	// Ensure interface index is valid
	ifIndex := opts.InterfaceIndex
	if ifIndex < 0 || ifIndex >= len(w.interfaces) {
		ifIndex = 0
	}

	// Write enhanced packet block
	return w.writeEnhancedPacket(uint32(ifIndex), timestamp, uint32(captureLength), uint32(length), payload, opts.Comment)
}

// Flush flushes any buffered data to the underlying writer.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	// No buffering in this implementation, so nothing to flush
	return nil
}

// Close flushes any buffered data and closes the writer.
// Note that this does not close the underlying io.Writer.
func (w *Writer) Close() error {
	return w.Flush()
}

// SetSectionComment sets a comment for the section header block.
// This method should be called before writing any packets.
// If the section header has already been written, this method has no effect.
func (w *Writer) SetSectionComment(comment string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.sectionWritten {
		w.sectionComment = comment
	}
}

// writeSectionHeader writes a section header block to the output.
func (w *Writer) writeSectionHeader() error {
	// Calculate block size
	blockLen := 28 // 4 (block type) + 4 (block length) + 4 (byte order magic) + 2 (major) + 2 (minor) + 8 (section length) + 0 (options) + 4 (block length repeated)

	// Calculate options size if comment is present
	optionsLen := 0
	if w.sectionComment != "" {
		// Comment option: 4 (type + length) + len(comment) + padding
		commentLen := len(w.sectionComment)
		padding := 4 - (commentLen % 4)
		if padding == 4 {
			padding = 0
		}
		optionsLen += 4 + commentLen + padding

		// End of options: 4 bytes
		optionsLen += 4

		// Add options size to block length
		blockLen += optionsLen
	}

	// Reset buffer
	buf := w.buf[:0]

	// Block type
	buf = binary.LittleEndian.AppendUint32(buf, blockTypeSectionHeader)

	// Block length
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Byte order magic
	buf = append(buf, magicNumber...)

	// Major version
	buf = binary.LittleEndian.AppendUint16(buf, 1)

	// Minor version
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	// Section length (use -1 for unknown)
	buf = binary.LittleEndian.AppendUint64(buf, 0xFFFFFFFFFFFFFFFF)

	// Add comment option if present
	if w.sectionComment != "" {
		buf, _ = w.writeOption(buf, optComment, []byte(w.sectionComment))
		buf, _ = w.writeEndOfOpts(buf)
	}

	// Block length (repeated)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Write to output
	_, err := w.w.Write(buf)
	if err != nil {
		return err
	}

	w.sectionWritten = true
	return nil
}

// writeInterfaceDescription writes an interface description block to the output.
func (w *Writer) writeInterfaceDescription(index int) error {
	if index < 0 || index >= len(w.interfaces) {
		return fmt.Errorf("invalid interface index: %d", index)
	}

	iface := w.interfaces[index]

	// Calculate block size
	blockLen := 20 // 4 (block type) + 4 (block length) + 2 (link type) + 2 (reserved) + 4 (snap len) + 0 (options) + 4 (block length repeated)

	// Reset buffer
	buf := w.buf[:0]

	// Block type
	buf = binary.LittleEndian.AppendUint32(buf, blockTypeInterfaceDescription)

	// Block length
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Link type
	buf = binary.LittleEndian.AppendUint16(buf, uint16(iface.linkType))

	// Reserved
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	// Snap len
	buf = binary.LittleEndian.AppendUint32(buf, iface.snapLen)

	// Block length (repeated)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Write to output
	_, err := w.w.Write(buf)
	return err
}

// writeOption appends an option to the buffer.
// Returns the number of bytes written (including padding).
func (w *Writer) writeOption(buf []byte, optType uint16, optValue []byte) ([]byte, int) {
	optLen := len(optValue)

	// Option type
	buf = binary.LittleEndian.AppendUint16(buf, optType)

	// Option length
	buf = binary.LittleEndian.AppendUint16(buf, uint16(optLen))

	// Option value
	buf = append(buf, optValue...)

	// Calculate padding
	padding := 4 - (optLen % 4)
	if padding == 4 {
		padding = 0
	}

	// Add padding
	for i := 0; i < padding; i++ {
		buf = append(buf, 0)
	}

	// Return total bytes written
	return buf, 4 + optLen + padding // 4 bytes for type and length + value length + padding
}

// writeEndOfOpts appends an end-of-options marker to the buffer.
func (w *Writer) writeEndOfOpts(buf []byte) ([]byte, int) {
	// End of options marker
	buf = binary.LittleEndian.AppendUint16(buf, optEndOfOpts)
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	return buf, 4
}

// writeEnhancedPacket writes an enhanced packet block to the output.
func (w *Writer) writeEnhancedPacket(interfaceID uint32, timestamp time.Time, captureLen, packetLen uint32, data []byte, comment string) error {
	// Calculate padding for packet data
	padding := 4 - (captureLen % 4)
	if padding == 4 {
		padding = 0
	}

	// Calculate block size
	blockLen := 32 + int(captureLen) + int(padding) // 4 (block type) + 4 (block length) + 4 (interface ID) + 8 (timestamp) + 4 (capture len) + 4 (packet len) + captureLen + padding + 0 (options) + 4 (block length repeated)

	// Calculate options size if comment is present
	optionsLen := 0
	if comment != "" {
		// Comment option: 4 (type + length) + len(comment) + padding
		commentLen := len(comment)
		commentPadding := 4 - (commentLen % 4)
		if commentPadding == 4 {
			commentPadding = 0
		}
		optionsLen += 4 + commentLen + commentPadding

		// End of options: 4 bytes
		optionsLen += 4

		// Add options size to block length
		blockLen += optionsLen
	}

	// Reset buffer
	buf := w.buf[:0]

	// Block type
	buf = binary.LittleEndian.AppendUint32(buf, blockTypeEnhancedPacket)

	// Block length
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Interface ID
	buf = binary.LittleEndian.AppendUint32(buf, interfaceID)

	ts := timestamp.UnixNano() / int64(time.Microsecond)

	// Timestamp (high+low)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(ts>>32))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(ts&0xFFFFFFFF))

	// Captured packet length
	buf = binary.LittleEndian.AppendUint32(buf, captureLen)

	// Original packet length
	buf = binary.LittleEndian.AppendUint32(buf, packetLen)

	// Packet data
	buf = append(buf, data[:captureLen]...)

	// Padding for packet data
	for i := 0; i < int(padding); i++ {
		buf = append(buf, 0)
	}

	// Add comment option if present
	if comment != "" {
		buf, _ = w.writeOption(buf, optComment, []byte(comment))
		buf, _ = w.writeEndOfOpts(buf)
	}

	// Block length (repeated)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(blockLen))

	// Write to output
	_, err := w.w.Write(buf)
	return err
}
