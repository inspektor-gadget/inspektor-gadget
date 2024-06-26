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
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

const (
	ParamMapIterInterval = "map-fetch-interval"
)

type mapIter struct {
	name          string
	mapName       string
	keyStructName string
	valStructName string

	ds          datasource.DataSource
	keyAccessor datasource.FieldAccessor
	valAccessor datasource.FieldAccessor

	interval time.Duration
}

func (i *ebpfInstance) populateMap(t btf.Type, varName string) error {
	i.logger.Debugf("populating map %q", varName)

	newVar := &ebpfVar{
		name:    varName,
		refType: reflect.TypeOf(&ebpf.Map{}),
		tags:    nil,
	}

	i.vars[varName] = newVar

	// Set variable to nil pointer to map, so it's present
	var nilVal *ebpf.Map
	i.gadgetCtx.SetVar(varName, nilVal)
	return nil
}

func (i *ebpfInstance) mapParams() api.Params {
	if len(i.mapIters) == 0 {
		return nil
	}
	return api.Params{
		{
			Key:          ParamMapIterInterval,
			Description:  "interval in ms in which to iterate over maps and emit",
			DefaultValue: "1000ms",
			TypeHint:     api.TypeString,
			Title:        "Map fetch interval",
		},
	}
}

func (i *ebpfInstance) evaluateMapParams(paramValues api.ParamValues) error {
	if len(i.mapIters) == 0 {
		return nil
	}

	globalDuration := time.Duration(0)

	for _, interval := range strings.Split(paramValues[ParamMapIterInterval], ",") {
		if interval == "" {
			continue
		}
		info := strings.SplitN(interval, ":", 2)
		dsName := ""
		interval := info[0]
		if len(info) > 1 {
			dsName = info[0]
			interval = info[1]
		}
		duration, err := time.ParseDuration(interval)
		if err != nil {
			return fmt.Errorf("invalid interval %q for map iteration: %w", interval, err)
		}
		if dsName == "" {
			globalDuration = duration
			continue
		}
		iter, ok := i.mapIters[dsName]
		if !ok {
			return fmt.Errorf("map iterator %q given in interval config not found", dsName)
		}
		iter.interval = duration
	}

	for _, iter := range i.mapIters {
		if iter.interval == 0 {
			iter.interval = globalDuration
		}
	}
	return nil
}

func (i *ebpfInstance) runMapIterators() error {
	for _, iter := range i.mapIters {
		iterMap, ok := i.collection.Maps[iter.mapName]
		if !ok {
			return fmt.Errorf("map %q not found", iter.mapName)
		}
		fetch := func() {
			p, err := iter.ds.NewPacketArray()
			if err != nil {
				i.logger.Errorf("error creating packet for map iterator: %v", err)
			}

			var prevKey []byte

			batchSize := 100 // discuss

			keySize := int(iterMap.KeySize())
			valSize := int(iterMap.ValueSize())
			for {
				keys := make([]byte, keySize*batchSize)
				vals := make([]byte, valSize*batchSize)
				keysPtr := Pointer{ptr: unsafe.Pointer(&keys[0])}
				valuesPtr := Pointer{ptr: unsafe.Pointer(&vals[0])}

				// TODO: use cilium lib once raw byte access has been added
				// TODO: open PR to actually make that happen
				nk := make([]byte, keySize)
				attr := MapLookupBatchAttr{
					MapFd:    uint32(iterMap.FD()),
					Keys:     keysPtr,
					Values:   valuesPtr,
					Count:    uint32(batchSize),
					OutBatch: Pointer{ptr: unsafe.Pointer(&nk[0])},
				}
				if prevKey != nil {
					attr.InBatch = Pointer{ptr: unsafe.Pointer(&prevKey[0])}
				}

				_, err := BPF(BPF_MAP_LOOKUP_AND_DELETE_BATCH, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
				if err != nil && !errors.Is(err, unix.ENOENT) {
					i.logger.Warnf("error from map iterator: %v", err)
					break
				}
				n := int(attr.Count)

				prevKey = nk
				for c := range n {
					d := p.New()
					iter.keyAccessor.Set(d, keys[keySize*c:keySize*(c+1)])
					iter.valAccessor.Set(d, vals[valSize*c:valSize*(c+1)])
					p.Append(d)
				}
				if errors.Is(err, unix.ENOENT) { // ebpf.ErrKeyNotExist when doing this with cilium/ebpf later on
					break
				}
			}
			iter.ds.EmitAndRelease(p)
		}
		go func() {
			if iter.interval == 0 {
				// Only a single time; is this really useful?
				fetch()
				return
			}
			ticker := time.NewTicker(iter.interval)
			for {
				select {
				case <-i.gadgetCtx.Context().Done():
					return
				case <-ticker.C:
					fetch()
				}
			}
		}()
	}
	return nil
}

func (i *ebpfInstance) populateMapIter(t btf.Type, varName string) error {
	i.logger.Debugf("populating mapiter %q", varName)

	info := strings.Split(varName, typeSplitter)
	if len(info) != 4 {
		return fmt.Errorf("invalid name for gadget_mapiter type: %q", varName)
	}

	name := info[0]
	mapName := info[1]
	keyName := info[2]
	valName := info[3]

	if _, ok := i.mapIters[name]; ok {
		return fmt.Errorf("duplicate map iterator %q", varName)
	}

	// Get types
	iterMap, ok := i.collectionSpec.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found in eBPF object", mapName)
	}

	var keyStruct *btf.Struct
	if err := i.collectionSpec.Types.TypeByName(keyName, &keyStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", keyName, err)
	}

	var valStruct *btf.Struct
	if err := i.collectionSpec.Types.TypeByName(valName, &valStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", valStruct, err)
	}

	if iterMap.KeySize != keyStruct.Size || iterMap.ValueSize != valStruct.Size {
		return fmt.Errorf("key/value sizes of map %q does not match size of structs", mapName)
	}

	err := i.populateStructDirect(iterMap.Key.(*btf.Struct))
	if err != nil {
		return fmt.Errorf("populating key struct for map iter %q: %w", varName, err)
	}

	err = i.populateStructDirect(iterMap.Value.(*btf.Struct))
	if err != nil {
		return fmt.Errorf("populating key struct for map iter %q: %w", varName, err)
	}

	iter := &mapIter{
		name:          name,
		mapName:       mapName,
		keyStructName: keyName,
		valStructName: valName,
	}
	i.mapIters[name] = iter
	return nil
}

// This is a patched version of their counterparts from cilium/ebpf; the upstream code doesn't allow reading bytes
// from maps but instead wants to deserialize itself. However, we need to deserialize with our own libraries and
// thus get the raw data from the map in a performant way.

const (
	BPF_MAP_LOOKUP_AND_DELETE_BATCH uintptr = 25
)

type Pointer struct {
	ptr unsafe.Pointer
}

type MapLookupBatchAttr struct {
	InBatch   Pointer
	OutBatch  Pointer
	Keys      Pointer
	Values    Pointer
	Count     uint32
	MapFd     uint32
	ElemFlags uint64
	Flags     uint64
}

func BPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		var err error
		if errNo != 0 {
			err = errNo
		}

		return r1, err
	}
}
