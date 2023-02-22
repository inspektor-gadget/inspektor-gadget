// Copyright 2019-2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"golang.org/x/sys/unix"
)

type perfEventHeader struct {
	Type uint32
	Misc uint16
	Size uint16
}

type perfEventSample struct {
	Size uint32
}

func getRingsNumber(perfReader *perf.Reader) int {
	v := reflect.ValueOf(perfReader)
	rings := reflect.Indirect(v).FieldByName("rings")

	return rings.Len()
}

func readOverWritable(reader *containerRingReader, callback func(record perf.Record, size uint32) error) error {
	// Get private field with reflect.
	v := reflect.ValueOf(reader.perfReader)
	rings := reflect.Indirect(v).FieldByName("rings")
	ringsNumber := rings.Len()

	// For each perf buffer, we have as many buffers than CPU.
	for i := 0; i < ringsNumber; i++ {
		ring := rings.Index(i)
		if ring.IsNil() {
			// The CPU is offline, skip it.
			continue
		}
		rr := reflect.Indirect(ring).FieldByName("ringReader")

		m := reflect.Indirect(rr).FieldByName("meta")
		meta := (*unix.PerfEventMmapPage)(unsafe.Pointer(m.Pointer()))

		// We need to load the Data_head each time we read to be sure to have the
		// last value.
		head := atomic.LoadUint64(&meta.Data_head)

		m = reflect.Indirect(rr).FieldByName("mask")
		mask := m.Uint()

		d := reflect.Indirect(rr).FieldByName("ring")
		bytes := d.Bytes()
		data := make([]byte, len(bytes))
		// We copy the buffer to avoid reading it while it is being written.
		copy(data, bytes)

		read := head

		// So, if between two calls to this function, the prod_pos did not move,
		// it means there is no new data, so we can skip this CPU rather than
		// dealing with data we already proceeded.
		if reader.previousHeadPos[i] == head {
			log.Debugf("Nothing happened: head = %d", head)

			continue
		}

		// Backward read it playing with head and mask.
		for read-head < mask {
			headerPointer := unsafe.Pointer(&data[read&mask])
			header := (*perfEventHeader)(headerPointer)

			// If size is 0, it means we read all the data
			// available in the buffer and jump on 0 data:
			//
			// prod_pos                         read_pos
			//     |                                |
			//     V                                V
			// +---+------+----------+-------+------+
			// |   |D....D|C........C|B.....B|A....A|
			// +---+------+----------+-------+------+
			if header == nil || header.Size == 0 {
				log.Debug("We read all data available!")

				break
			}

			// If adding the event size to the current
			// consumer position makes us wrap the buffer,
			// it means we already did "one loop" around the
			// buffer.
			// So, the pointed data would not be usable:
			//
			//                               prod_pos
			//                   read_pos----+   |
			//                               |   |
			//                               V   V
			// +---+------+----------+-------+---+--+
			// |..E|D....D|C........C|B.....B|A..|E.|
			// +---+------+----------+-------+---+--+
			if read-head+uint64(header.Size) > mask {
				log.Debug("We wrapped the buffer!")

				break
			}

			if header.Type != unix.PERF_RECORD_SAMPLE {
				log.Warnf("received type %d while we only care of PERF_RECORD_SAMPLE (%d)", header.Type, unix.PERF_RECORD_SAMPLE)

				read += uint64(header.Size)

				// This prevents reading data we already processed.
				if reader.previousHeadPos[i] != 0 && read >= reader.previousHeadPos[i] {
					log.Debugf("We already read this!")

					break
				}
			}

			read += uint64(unsafe.Sizeof(*header))

			sample := (*perfEventSample)(unsafe.Pointer(&data[read&mask]))
			if sample == nil {
				reader.previousHeadPos[i] = head

				return fmt.Errorf("cannot get a sample event while event type is PERF_RECORD_SAMPLE")
			}

			size := sample.Size
			record := perf.Record{RawSample: make([]byte, size)}

			read += uint64(unsafe.Sizeof(*sample))
			previousReadMasked := read & mask

			read += uint64(size)

			log.Debugf("header: %v; read: %v; head: %v; previousHeadPos: %v; previousReadMasked: %v", header, read&mask, head&mask, reader.previousHeadPos[i]&mask, previousReadMasked)

			// If adding the event size to the current
			// consumer position makes us going from end of the buffer toward the
			// start, we need to copy the data in two times:
			// 1. First from previous_read_pos until end of the buffer.
			// 2. Second from start of the buffer until read_pos.
			//
			// read_pos                  previous_read_pos
			//     |                             |
			//     V                             V
			// +---+------+----------+-------+---+--+
			// |..E|D....D|C........C|B.....B|A..|E.|
			// +---+------+----------+-------+---+--+
			// This code snippet was highly inspired by gobpf:
			// https://github.com/iovisor/gobpf/blob/16120a1bf4d4abc1f9cf37fecfb86009a1631b9f/elf/perf.go#L148
			if (read & mask) < previousReadMasked {
				// Compute the number of bytes from the beginning of this sample until
				// the end of the buffer.
				length := uint32(mask + 1 - previousReadMasked)

				log.Debugf("length: %v", length)

				// From previousRead until end of the buffer.
				copy(record.RawSample[0:length-1], unsafe.Slice((*byte)(unsafe.Pointer(&data[previousReadMasked])), length))
				// From beginning of the buffer until read.
				copy(record.RawSample[length:], data[0:size-length])
			} else {
				// We are in the "middle" of the buffer, so no worries!
				copy(record.RawSample, unsafe.Slice((*byte)(unsafe.Pointer(&data[previousReadMasked])), size))
			}

			err := callback(record, size)
			if err != nil {
				reader.previousHeadPos[i] = head
				return err
			}

			// This prevents reading data we already processed.
			if reader.previousHeadPos[i] != 0 && read >= reader.previousHeadPos[i] {
				log.Debug("We already read this!")

				break
			}
		}

		reader.previousHeadPos[i] = head
	}

	return nil
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
func roundUp(x, y uintptr) uintptr {
	return ((x - 1) | (y - 1)) + 1
}

// The kernel aligns size of perf event with the following snippet:
// void perf_prepare_sample(...)
//
//	{
//		//...
//		size = round_up(sum + sizeof(u32), sizeof(u64));
//		raw->size = size - sizeof(u32);
//		frag->pad = raw->size - sum;
//		// ...
//	}
//
// (https://elixir.bootlin.com/linux/v6.0/source/kernel/events/core.c#L7353)
// In the case of our structure of interest (i.e. struct_syscall_event_t and
// struct_syscall_event_cont_t), their size will be increased by 4, here is
// an example for struct_syscall_event_t which size is 88:
// size = round_up(sum + sizeof(u32), sizeof(u64))
//
//	= round_up(88 + 4, 8)
//	= round_up(92, 8)
//	= 96
//
// raw->size = size - sizeof(u32)
//
//	= 96 - 4
//	= 92
//
// So, 4 bytes will be added as padding at the end of the event and the size we
// will read getting perfEventSample will be 92 instead of 88.
func alignSize(structSize uintptr) uintptr {
	var ret uintptr
	var foo uint64
	var bar uint32

	ret = roundUp(structSize+unsafe.Sizeof(bar), unsafe.Sizeof(foo))
	ret = ret - unsafe.Sizeof(bar)

	return ret
}
