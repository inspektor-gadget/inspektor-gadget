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
	"strings"

	"github.com/cilium/ebpf/btf"
)

type dataSourceType int

const (
	tracer dataSourceType = iota
	snapshotter
)

type dataSource struct {
	typ      dataSourceType
	eMap     string
	dataType string
	programs map[string]struct{}
}

func (i *ebpfInstance) parseDataSource(members []btf.Member) (*dataSource, error) {
	ds := &dataSource{
		programs: make(map[string]struct{}),
	}

	for _, member := range members {
		switch member.Name {
		case "ds_type":
			btfPtr, ok := member.Type.(*btf.Pointer)
			if !ok {
				return nil, fmt.Errorf("%q is not a pointer", member.Name)
			}

			btfArray, ok := btfPtr.Target.(*btf.Array)
			if !ok {
				return nil, fmt.Errorf("%q is not an array", member.Name)
			}

			_, ok = btfArray.Type.(*btf.Int)
			if !ok {
				return nil, fmt.Errorf("%q is not an int", member.Name)
			}

			ds.typ = dataSourceType(btfArray.Nelems)
			i.logger.Debugf(">> dsType %d", ds.typ)
		case "data_type":
			btfPtr, ok := member.Type.(*btf.Pointer)
			if !ok {
				return nil, fmt.Errorf("%q is not a pointer", member.Name)
			}

			btfStruct, ok := btfPtr.Target.(*btf.Struct)
			if !ok {
				return nil, fmt.Errorf("%q is not a struct", member.Name)
			}

			ds.dataType = btfStruct.TypeName()
			i.logger.Debugf(">> dataType %q", ds.dataType)
		default:
			btfPtr, ok := member.Type.(*btf.Pointer)
			if !ok {
				return nil, fmt.Errorf("%q is not a pointer", member.Name)
			}

			_, ok = btfPtr.Target.(*btf.Void)
			if !ok {
				return nil, fmt.Errorf("%q is not a void", member.Name)
			}

			parts := strings.Split(member.Name, typeSplitter)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid member %q", member.Name)
			}

			if parts[0] == "program" {
				progName := parts[1]
				ds.programs[progName] = struct{}{}
				i.logger.Debugf(">> program %q", progName)
			} else if parts[0] == "map" {
				if ds.eMap != "" {
					return nil, errors.New("multiple maps")
				}
				ds.eMap = parts[1]
				i.logger.Debugf(">> map %q", ds.eMap)
			} else {
				return nil, fmt.Errorf("unknown member %q", member.Name)
			}
		}
	}

	return ds, nil
}

func (i *ebpfInstance) populateDataSources(t btf.Type, varName string) error {
	btfDatasec, ok := t.(*btf.Datasec)
	if !ok {
		return fmt.Errorf("%q not of type *btf.Datasec", varName)
	}

	i.logger.Debug("populating datasources")

	for _, v := range btfDatasec.Vars {
		dsName := v.Type.TypeName()

		btfVar, ok := v.Type.(*btf.Var)
		if !ok {
			return fmt.Errorf("%q not of type *btf.Var", dsName)
		}

		btfStruct, ok := btfVar.Type.(*btf.Struct)
		if !ok {
			return fmt.Errorf("%q not a struct", dsName)
		}

		i.logger.Debugf("> datasource %q", dsName)

		ds, err := i.parseDataSource(btfStruct.Members)
		if err != nil {
			return fmt.Errorf("building datasource %q: %w", dsName, err)
		}

		switch ds.typ {
		case tracer:
			if err := i.populateTracer(dsName, ds); err != nil {
				return fmt.Errorf("populating tracer %q: %w", dsName, err)
			}
		case snapshotter:
			if err := i.populateSnapshotter(dsName, ds); err != nil {
				return fmt.Errorf("populating snapshotter %q: %w", dsName, err)
			}
		default:
			return fmt.Errorf("unknown datasource type %d", ds.typ)
		}
	}

	return nil
}
