// Copyright 2024-2025 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type Tracer struct {
	mapName    string
	structName string

	ds              datasource.DataSource
	accessor        datasource.FieldAccessor
	restAccessor    datasource.FieldAccessor
	restLenAccessor datasource.FieldAccessor

	mapType       ebpf.MapType
	eventSize     uint32 // needed to trim trailing bytes when reading for perf event array
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader
	slowBuf       []byte
}

func validateTracerMap(traceMap *ebpf.MapSpec) error {
	if traceMap.Type != ebpf.RingBuf && traceMap.Type != ebpf.PerfEventArray {
		return fmt.Errorf("map %q has a wrong type, expected: ringbuf or perf event array, got: %s",
			traceMap.Name, traceMap.Type.String())
	}
	return nil
}

// fixTracerMap updates the tracer map type in case ringbuf is not available.
func (i *ebpfInstance) fixTracerMap(t btf.Type, varName string) error {
	bufMap, ok := i.collectionSpec.Maps[varName]
	if !ok {
		return fmt.Errorf("map %q not found in eBPF object", varName)
	}

	if !isRingbufAvailable() {
		bufMap.Type = ebpf.PerfEventArray
		bufMap.KeySize = 4
		bufMap.ValueSize = 4
	}

	return nil
}

func (i *ebpfInstance) populateTracer(t btf.Type, varName string) error {
	i.logger.Debugf("populating tracer %q", varName)

	parts := strings.Split(varName, typeSplitter)
	if len(parts) != 3 {
		return fmt.Errorf("invalid tracer info: %q", varName)
	}

	name := parts[0]
	mapName := parts[1]
	structName := parts[2]

	i.logger.Debugf("> name       : %q", name)
	i.logger.Debugf("> map name   : %q", mapName)
	i.logger.Debugf("> struct name: %q", structName)

	tracerMap, ok := i.collectionSpec.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found in eBPF object", mapName)
	}

	if err := validateTracerMap(tracerMap); err != nil {
		return fmt.Errorf("trace map is invalid: %w", err)
	}

	var btfStruct *btf.Struct
	if err := i.collectionSpec.Types.TypeByName(structName, &btfStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", structName, err)
	}

	i.logger.Debugf("adding tracer %q", name)
	i.tracers[name] = &Tracer{
		mapName:    mapName,
		structName: btfStruct.Name,
		eventSize:  btfStruct.Size,
	}

	err := i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for tracer %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (t *Tracer) receiveEvents(gadgetCtx operators.GadgetContext, wg *sync.WaitGroup) error {
	defer wg.Done()

	var readCb func() (data []byte, lost uint64, err error)

	switch t.mapType {
	case ebpf.RingBuf:
		readCb = func() ([]byte, uint64, error) {
			rec, err := t.ringbufReader.Read()
			return rec.RawSample, 0, err
		}
	case ebpf.PerfEventArray:
		readCb = func() ([]byte, uint64, error) {
			rec, err := t.perfReader.Read()
			return rec.RawSample, rec.LostSamples, err
		}
	default:
		return fmt.Errorf("invalid map type")
	}

	t.slowBuf = make([]byte, t.eventSize)
	for {
		sample, lost, err := readCb()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return err
			}
			gadgetCtx.Logger().Warnf("error reading event: %v", err)
			continue
		}

		if lost > 0 {
			gadgetCtx.Logger().Warnf("reading event: lost %d samples", lost)
			t.ds.ReportLostData(lost)
			continue
		}

		if err := t.processEvent(gadgetCtx, sample); err != nil {
			gadgetCtx.Logger().Warnf("error processing event: %v", err)
			continue
		}
	}
}

func (t *Tracer) processEvent(gadgetCtx operators.GadgetContext, fullSample []byte) error {
	pSingle, err := t.ds.NewPacketSingle()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	sample := fullSample
	sampleLen := uint32(len(fullSample))
	if sampleLen < t.eventSize {
		// event is truncated; we need to copy
		copy(t.slowBuf, fullSample)

		// zero difference; TODO: improve
		for i := len(fullSample); i < int(t.eventSize); i++ {
			t.slowBuf[i] = 0
		}
		sample = t.slowBuf
	} else if sampleLen > t.eventSize {
		// event has trailing garbage, remove it
		sample = sample[:t.eventSize]
	}

	if err := t.accessor.Set(pSingle, sample); err != nil {
		t.ds.Release(pSingle)
		return fmt.Errorf("setting buffer: %w", err)
	}

	if t.restAccessor != nil && sampleLen > t.eventSize {
		xlen := sampleLen - t.eventSize

		if t.restLenAccessor != nil {
			// Read length
			xlen, err = t.restLenAccessor.Uint32(pSingle)
			if err != nil {
				return fmt.Errorf("getting rest length: %w", err)
			}

			if t.eventSize+xlen > sampleLen {
				return fmt.Errorf("rest length %d is larger than data length %d - event size %d",
					xlen, sampleLen, t.eventSize)
			}
		}

		t.restAccessor.Set(pSingle, fullSample[t.eventSize:t.eventSize+xlen])
	}

	if err := t.ds.EmitAndRelease(pSingle); err != nil {
		return fmt.Errorf("emitting data: %w", err)
	}

	return nil
}

func (t *Tracer) close() {
	if t.ringbufReader != nil {
		t.ringbufReader.Close()
	}
	if t.perfReader != nil {
		t.perfReader.Close()
	}
}

func (i *ebpfInstance) runTracer(gadgetCtx operators.GadgetContext, tracer *Tracer) error {
	if tracer.mapName == "" {
		return fmt.Errorf("tracer map name empty")
	}

	m, ok := i.collection.Maps[tracer.mapName]
	if !ok {
		return fmt.Errorf("looking up tracer map %q: not found", tracer.mapName)
	}

	tracer.mapType = m.Type()

	var err error
	switch m.Type() {
	case ebpf.RingBuf:
		i.logger.Debugf("creating ringbuf reader for map %q", tracer.mapName)
		tracer.ringbufReader, err = ringbuf.NewReader(m)
	case ebpf.PerfEventArray:
		i.logger.Debugf("creating perf reader for map %q", tracer.mapName)
		tracer.perfReader, err = perf.NewReader(m, gadgets.PerfBufferPages*os.Getpagesize())
	default:
		return fmt.Errorf("unknown type for tracer map %q", tracer.mapName)
	}
	if err != nil {
		return fmt.Errorf("creating BPF map reader: %w", err)
	}

	// TODO: freezing ringbuf doesn't work: "device or resource busy"
	if m.Type() == ebpf.PerfEventArray {
		if err := gadgets.FreezeMaps(m); err != nil {
			return err
		}
	}

	i.wg.Add(1)
	go tracer.receiveEvents(gadgetCtx, &i.wg)

	return nil
}
