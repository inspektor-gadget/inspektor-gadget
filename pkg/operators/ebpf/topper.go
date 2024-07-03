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
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type Topper struct {
	metadatav1.Topper

	ds        datasource.DataSource
	accessor  datasource.FieldAccessor
	topperMap *ebpf.Map
}

func validateTopperMap(topperMap *ebpf.MapSpec, expectedStructName string) error {
	if topperMap.Type != ebpf.Hash {
		return fmt.Errorf("map %q has a wrong type, expected: hash, got: %s",
			topperMap.Name, topperMap.Type)
	}

	if topperMap.Value == nil {
		return fmt.Errorf("map %q does not have BTF information for its values", topperMap.Name)
	}

	topperMapStruct, ok := topperMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("map %q value is %q, expected \"struct\"",
			topperMap.Name, topperMap.Value.TypeName())
	}

	if expectedStructName != "" && topperMapStruct.Name != expectedStructName {
		return fmt.Errorf("map %q value name is %q, expected %q",
			topperMap.Name, topperMapStruct.Name, expectedStructName)
	}

	return nil
}

func (i *ebpfInstance) populateTopper(t btf.Type, varName string) error {
	i.logger.Debugf("populating topper %q", varName)

	parts := strings.Split(varName, typeSplitter)
	if len(parts) != 2 {
		return fmt.Errorf("invalid topper info: %q", varName)
	}

	name := parts[0]
	mapName := parts[1]

	i.logger.Debugf("> name    : %q", name)
	i.logger.Debugf("> map name: %q", mapName)

	var structName string

	tracerConfig := i.config.Sub("toppers." + name)
	if tracerConfig != nil {
		if configMapName := tracerConfig.GetString("mapName"); configMapName != "" && configMapName != mapName {
			return fmt.Errorf("validating topper %q: mapName %q in eBPF program does not match %q from metadata file",
				name, configMapName, mapName)
		}
		structName = tracerConfig.GetString("structName")

		i.logger.Debugf("> successfully validated with metadata")
	}

	if _, ok := i.toppers[name]; ok {
		i.logger.Debugf("topper %q already defined, skipping", name)
		return nil
	}

	topperMapSpec, ok := i.collectionSpec.Maps[mapName]
	if !ok {
		return fmt.Errorf("map %q not found in eBPF object", mapName)
	}

	if err := validateTopperMap(topperMapSpec, structName); err != nil {
		return fmt.Errorf("topper map is invalid: %w", err)
	}

	btfStruct := topperMapSpec.Value.(*btf.Struct)

	i.logger.Debugf("adding topper %q", name)
	i.toppers[name] = &Topper{
		Topper: metadatav1.Topper{
			MapName:    mapName,
			StructName: btfStruct.Name,
		},
	}

	err := i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for topper %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (t *Topper) nextStats(gadgetCtx operators.GadgetContext, pArray datasource.PacketArray) error {
	entries := t.topperMap
	logger := gadgetCtx.Logger()

	defer func() {
		// Delete elements. TODO: We should ensure to delete only the elements
		// we read to avoid deleting elements that are not read yet.
		key, err := entries.NextKeyBytes(nil)
		if err != nil {
			logger.Warnf("couldn't get first key to delete: %v", err)
			return
		}
		if key == nil {
			// Map is empty
			return
		}

		for {
			if err := entries.Delete(key); err != nil {
				logger.Warnf("couldn't delete value from key: %v", err)
				return
			}
			key, err = entries.NextKeyBytes(key)
			if err != nil {
				return
			}
			if key == nil {
				// No more keys
				break
			}
		}
	}()

	// Gather elements: Start by getting the first key
	key, err := entries.NextKeyBytes(nil)
	if err != nil {
		return fmt.Errorf("getting first key: %w", err)
	}
	if key == nil {
		// Map is empty
		return nil
	}

	// Now iterate over all keys
	for {
		var rawStat []byte
		rawStat, err := entries.LookupBytes(key)
		if err != nil {
			return fmt.Errorf("looking up value from key: %w", err)
		}

		data := pArray.New()
		t.accessor.Set(data, rawStat)
		pArray.Append(data)

		key, err = entries.NextKeyBytes(key)
		if err != nil {
			return fmt.Errorf("getting next key: %w", err)
		}
		if key == nil {
			// No more keys
			break
		}
	}

	return nil
}

func (t *Topper) readEntries(gadgetCtx operators.GadgetContext) error {
	pArray, err := t.ds.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	if err := t.nextStats(gadgetCtx, pArray); err != nil {
		t.ds.Release(pArray)
		return fmt.Errorf("reading stats: %w", err)
	}

	if err := t.ds.EmitAndRelease(pArray); err != nil {
		return fmt.Errorf("emitting topper data: %w", err)
	}

	return nil
}

func (i *ebpfInstance) runTopper(gadgetCtx operators.GadgetContext, topper *Topper, interval time.Duration) error {
	if topper.MapName == "" {
		return fmt.Errorf("topper map name empty")
	}

	m, ok := i.collection.Maps[topper.MapName]
	if !ok {
		return fmt.Errorf("looking up topper map %q: not found", topper.MapName)
	}
	topper.topperMap = m

	go func() {
		// TODO: This should be configurable
		ticker := time.NewTicker(interval)

		for {
			select {
			case <-gadgetCtx.Context().Done():
				return
			case <-ticker.C:
				if err := topper.readEntries(gadgetCtx); err != nil {
					gadgetCtx.Logger().Errorf("reading entries from topper %v", err)
				}
			}
		}
	}()

	return nil
}
