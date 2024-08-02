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
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
)

const (
	ParamMapIterInterval = "map-fetch-interval"
	ParamMapIterCount    = "map-fetch-count"
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
	count    int
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
			Description:  "interval in which to iterate over maps",
			DefaultValue: "1000ms",
			TypeHint:     api.TypeString,
			Title:        "Map fetch interval",
		},
		{
			Key:          ParamMapIterCount,
			Description:  "number of map fetch cycles - use 0 for unlimited",
			DefaultValue: "0",
			TypeHint:     api.TypeInt,
			Title:        "Map fetch count",
		},
	}
}

func (i *ebpfInstance) evaluateMapParams(paramValues api.ParamValues) error {
	if len(i.mapIters) == 0 {
		return nil
	}

	globalDuration := time.Duration(0)
	globalCount := 0

	durations, err := apihelpers.GetDurationValuesPerDataSource(paramValues[ParamMapIterInterval])
	if err != nil {
		return fmt.Errorf("evaluating map fetch interval: %w", err)
	}
	for dsName, duration := range durations {
		if dsName == "" {
			globalDuration = duration
			continue
		}
		iter, ok := i.mapIters[dsName]
		if !ok {
			return fmt.Errorf("map fetch interval found for non-existing iterator %q", dsName)
		}
		iter.interval = duration
	}

	counts, err := apihelpers.GetIntValuesPerDataSource(paramValues[ParamMapIterCount])
	if err != nil {
		return fmt.Errorf("evaluating map fetch interval: %w", err)
	}
	for dsName, count := range counts {
		if dsName == "" {
			globalCount = count
			continue
		}
		iter, ok := i.mapIters[dsName]
		if !ok {
			return fmt.Errorf("map fetch count found for non-existing iterator %q", dsName)
		}
		iter.count = count
	}

	for _, iter := range i.mapIters {
		if iter.interval == 0 {
			iter.interval = globalDuration
		}
		if iter.count == 0 {
			iter.count = globalCount
		}
		iter.ds.AddAnnotation(api.FetchCountAnnotation, fmt.Sprintf("%d", iter.count))
		iter.ds.AddAnnotation(api.FetchIntervalAnnotation, iter.interval.String())
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
				return
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
			ctr := 0
			ticker := time.NewTicker(iter.interval)
			for {
				select {
				case <-i.gadgetCtx.Context().Done():
					return
				case <-ticker.C:
					fetch()
					ctr++
					if iter.count > 0 && ctr >= iter.count {
						// TODO: close DS
						return
					}
				}
			}
		}()
	}
	return nil
}

func (i *ebpfInstance) populateMapIter(t btf.Type, varName string) error {
	i.logger.Debugf("populating mapiter %q", varName)

	info := strings.Split(varName, typeSplitter)
	if len(info) != 2 {
		return fmt.Errorf("invalid name for gadget_mapiter type: %q", varName)
	}

	name := info[0]
	mapName := info[1]

	if _, ok := i.mapIters[name]; ok {
		return fmt.Errorf("duplicate map iterator %q", varName)
	}

	// Get types
	iterMap, ok := i.collectionSpec.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found in eBPF object", mapName)
	}

	keyStruct, ok := iterMap.Key.(*btf.Struct)
	if !ok {
		return fmt.Errorf("map %q key is not a struct", mapName)
	}

	valStruct, ok := iterMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("map %q value is not a struct", mapName)
	}

	if iterMap.KeySize != keyStruct.Size || iterMap.ValueSize != valStruct.Size {
		return fmt.Errorf("key/value sizes of map %q does not match size of structs", mapName)
	}

	err := i.populateStructDirect(keyStruct)
	if err != nil {
		return fmt.Errorf("populating key struct for map iter %q: %w", varName, err)
	}

	err = i.populateStructDirect(valStruct)
	if err != nil {
		return fmt.Errorf("populating value struct for map iter %q: %w", varName, err)
	}

	iter := &mapIter{
		name:          name,
		mapName:       mapName,
		keyStructName: keyStruct.Name,
		valStructName: valStruct.Name,
	}
	i.mapIters[name] = iter
	return nil
}
