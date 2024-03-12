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

	"github.com/cilium/ebpf/btf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func byteSliceAsUint64(in []byte, signed bool, ds datasource.DataSource) uint64 {
	if signed {
		switch len(in) {
		case 1:
			return uint64(int8(in[0]))
		case 2:
			return uint64(int16(ds.ByteOrder().Uint16(in)))
		case 4:
			return uint64(int32(ds.ByteOrder().Uint32(in)))
		case 8:
			return uint64(int64(ds.ByteOrder().Uint64(in)))
		}
	}

	switch len(in) {
	case 1:
		return uint64(in[0])
	case 2:
		return uint64(ds.ByteOrder().Uint16(in))
	case 4:
		return uint64(ds.ByteOrder().Uint32(in))
	case 8:
		return uint64(ds.ByteOrder().Uint64(in))
	}

	return 0
}

func (i *ebpfInstance) initEnumConverter(gadgetCtx operators.GadgetContext) error {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		i.logger.Warnf("Kernel BTF information not available. Enums won't be resolved to strings")
	}

	for _, ds := range gadgetCtx.GetDataSources() {
		var converters []func(ds datasource.DataSource, data datasource.Data) error

		for name, enum := range i.enums {
			in := ds.GetField(name)
			if in == nil {
				continue
			}
			in.SetHidden(true, false)

			if btfSpec != nil {
				kernelEnum := &btf.Enum{}
				if err = btfSpec.TypeByName(enum.Name, &kernelEnum); err == nil {
					// Use kernel enum if found
					enum = kernelEnum
				}
			}

			out, err := ds.AddField(name + "_str")
			if err != nil {
				return err
			}

			converter := func(ds datasource.DataSource, data datasource.Data) error {
				// TODO: lookup table?
				inBytes := in.Get(data)
				val := byteSliceAsUint64(inBytes, enum.Signed, ds)
				for _, v := range enum.Values {
					if val == v.Value {
						out.Set(data, []byte(v.Name))
						return nil
					}
				}
				out.Set(data, []byte("UNKNOWN"))
				return nil
			}

			converters = append(converters, converter)
		}

		if len(converters) > 0 {
			i.converters[ds] = converters
		}
	}

	return nil
}

func (i *ebpfInstance) initConverters(gadgetCtx operators.GadgetContext) error {
	if err := i.initEnumConverter(gadgetCtx); err != nil {
		return fmt.Errorf("initializing enum converters: %w", err)
	}

	return nil
}
