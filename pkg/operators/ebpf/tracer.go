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

package ebpfoperator

import (
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type Tracer struct {
	metadatav1.Tracer

	ds       datasource.DataSource
	accessor datasource.FieldAccessor

	mapType       ebpf.MapType
	eventSize     uint32 // needed to trim trailing bytes when reading for perf event array
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader
}

func validateTracerMap(traceMap *ebpf.MapSpec) error {
	if traceMap.Type != ebpf.RingBuf && traceMap.Type != ebpf.PerfEventArray {
		return fmt.Errorf("map %q has a wrong type, expected: ringbuf or perf event array, got: %s",
			traceMap.Name, traceMap.Type.String())
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
		Tracer: metadatav1.Tracer{
			MapName:    mapName,
			StructName: btfStruct.Name,
		},
		eventSize: btfStruct.Size,
	}

	err := i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for tracer %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (t *Tracer) receiveEvents(gadgetCtx operators.GadgetContext) error {
	switch t.mapType {
	case ebpf.RingBuf:
		return t.receiveEventsFromRingReader(gadgetCtx)
	case ebpf.PerfEventArray:
		return t.receiveEventsFromPerfReader(gadgetCtx)
	default:
		return fmt.Errorf("invalid map type")
	}
}

func (t *Tracer) receiveEventsFromRingReader(gadgetCtx operators.GadgetContext) error {
	slowBuf := make([]byte, t.eventSize)
	lastSlowLen := 0
	for {
		rec, err := t.ringbufReader.Read()
		if err != nil {
			return err
		}
		pSingle, err := t.ds.NewPacketSingle()
		if err != nil {
			gadgetCtx.Logger().Warnf("error creating new packet: %v", err)
			continue
		}
		sample := rec.RawSample
		if uint32(len(rec.RawSample)) < t.eventSize {
			// event is truncated; we need to copy
			copy(slowBuf, rec.RawSample)

			// zero difference; TODO: improve
			if len(rec.RawSample) < lastSlowLen {
				for i := len(rec.RawSample); i < lastSlowLen; i++ {
					slowBuf[i] = 0
				}
			}
			lastSlowLen = len(rec.RawSample)
			sample = slowBuf
		}
		err = t.accessor.Set(pSingle, sample)
		if err != nil {
			gadgetCtx.Logger().Warnf("error setting buffer: %v", err)
			t.ds.Release(pSingle)
			continue
		}
		err = t.ds.EmitAndRelease(pSingle)
		if err != nil {
			gadgetCtx.Logger().Warnf("error emitting data: %v", err)
		}
	}
}

func (t *Tracer) receiveEventsFromPerfReader(gadgetCtx operators.GadgetContext) error {
	slowBuf := make([]byte, t.eventSize)
	lastSlowLen := 0
	for {
		rec, err := t.perfReader.Read()
		if err != nil {
			return err
		}
		pSingle, err := t.ds.NewPacketSingle()
		if err != nil {
			gadgetCtx.Logger().Warnf("error creating new packet: %v", err)
			continue
		}
		sample := rec.RawSample
		sampleLen := len(rec.RawSample)
		if uint32(sampleLen) < t.eventSize {
			// event is truncated; we need to copy
			copy(slowBuf, rec.RawSample)

			// zero difference; TODO: improve
			if sampleLen < lastSlowLen {
				for i := sampleLen; i < lastSlowLen; i++ {
					slowBuf[i] = 0
				}
			}
			lastSlowLen = sampleLen
			sample = slowBuf
		} else if uint32(sampleLen) > t.eventSize {
			// event has trailing garbage, remove it
			sample = sample[:t.eventSize]
		}
		err = t.accessor.Set(pSingle, sample)
		if err != nil {
			gadgetCtx.Logger().Warnf("error setting buffer: %v", err)
			t.ds.Release(pSingle)
			continue
		}
		err = t.ds.EmitAndRelease(pSingle)
		if err != nil {
			gadgetCtx.Logger().Warnf("error emitting data: %v", err)
		}
		if rec.LostSamples > 0 {
			t.ds.ReportLostData(rec.LostSamples)
		}
	}
}

func (i *ebpfInstance) runTracer(gadgetCtx operators.GadgetContext, tracer *Tracer) error {
	if tracer.MapName == "" {
		return fmt.Errorf("tracer map name empty")
	}

	m, ok := i.collection.Maps[tracer.MapName]
	if !ok {
		return fmt.Errorf("looking up tracer map %q: not found", tracer.MapName)
	}

	tracer.mapType = m.Type()

	var err error
	switch m.Type() {
	case ebpf.RingBuf:
		i.logger.Debugf("creating ringbuf reader for map %q", tracer.MapName)
		tracer.ringbufReader, err = ringbuf.NewReader(m)
	case ebpf.PerfEventArray:
		i.logger.Debugf("creating perf reader for map %q", tracer.MapName)
		tracer.perfReader, err = perf.NewReader(m, gadgets.PerfBufferPages*os.Getpagesize())
	default:
		return fmt.Errorf("unknown type for tracer map %q", tracer.MapName)
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

	go tracer.receiveEvents(gadgetCtx)

	<-gadgetCtx.Context().Done()

	if tracer.ringbufReader != nil {
		tracer.ringbufReader.Close()
	}
	if tracer.perfReader != nil {
		tracer.perfReader.Close()
	}
	return nil
}
