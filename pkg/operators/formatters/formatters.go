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

package formatters

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

// Keep this aligned with include/gadget/types.h
const (
	// L3EndpointTypeName contains the name of the type that gadgets should use to store an L3 endpoint.
	L3EndpointTypeName = "gadget_l3endpoint_t"

	// L4EndpointTypeName contains the name of the type that gadgets should use to store an L4 endpoint.
	L4EndpointTypeName = "gadget_l4endpoint_t"

	// TimestampTypeName contains the name of the type to store a timestamp
	TimestampTypeName = "gadget_timestamp"
)

type formattersOperator struct{}

func (f *formattersOperator) Name() string {
	return "formatters"
}

func (f *formattersOperator) Init(params *params.Params) error {
	return nil
}

func (f *formattersOperator) GlobalParams() api.Params {
	return nil
}

func (f *formattersOperator) InstanceParams() api.Params {
	return nil
}

func (f *formattersOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (operators.DataOperatorInstance, error) {
	inst := &formattersOperatorInstance{
		converters: make(map[datasource.DataSource][]converter),
	}
	logger := gadgetCtx.Logger()
	// Find things we can enrich
	for _, ds := range gadgetCtx.GetDataSources() {
		var converters []converter
		logger.Debugf("formatterOperator inspecting datasource %q", ds.Name())
		for _, r := range replacers {
			fields := ds.GetFieldsWithTag(r.selectors...)
			if len(fields) == 0 {
				continue
			}
			logger.Debugf("> found %d fields for replacer %v", len(fields), r.selectors)
			for _, field := range fields {
				replFunc, err := r.replace(ds, field)
				if err != nil {
					logger.Debugf(">  skipping field %q: %v", field.Name(), err)
					continue
				}
				if replFunc == nil {
					continue
				}
				converters = append(converters, converter{
					name:     r.name,
					src:      field,
					replacer: replFunc,
					priority: r.priority,
				})
			}
		}
		if len(converters) > 0 {
			inst.converters[ds] = converters
		}
	}
	// Don't run, if we don't have anything to do
	if len(inst.converters) == 0 {
		return nil, nil
	}

	return inst, nil
}

type converter struct {
	name     string
	src      datasource.FieldAccessor
	replacer func(datasource.Data) error
	priority int
}

type replacer struct {
	name string

	// selectors describes which fields to look for
	selectors []string

	// replace will be called for incoming data with the source and target fields set
	replace func(datasource.DataSource, datasource.FieldAccessor) (func(datasource.Data) error, error)

	// priority to be used when subscribing to the DataSource
	priority int
}

// careful: order and priority matter both!
var replacers = []replacer{
	{
		name:      "timestamp",
		selectors: []string{"type:" + TimestampTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			// Read annotations to allow user-defined behavior; this needs to be documented // TODO
			annotations := in.Annotations()

			// remove reference to old field for backwards compatibility
			in.RemoveReference(false)

			timestampFormat := "2006-01-02T15:04:05.000000000Z07:00"
			if format := annotations["formatters.timestamp.format"]; format != "" {
				timestampFormat = format
			}

			outName := in.Name()
			if out := annotations["formatters.timestamp.target"]; out != "" {
				outName = out
			}

			out, err := ds.AddField(outName)
			if err != nil {
				return nil, nil
			}

			return func(data datasource.Data) error {
				inBytes := in.Get(data)
				switch len(inBytes) {
				default:
					return nil
				case 8:
					// TODO: WallTimeFromBootTime() converts too much for this, create a new func that does less
					correctedTime := gadgets.WallTimeFromBootTime(ds.ByteOrder().Uint64(inBytes))
					ds.ByteOrder().PutUint64(inBytes, uint64(correctedTime))
					t := time.Unix(0, int64(correctedTime))
					return out.Set(data, []byte(t.Format(timestampFormat)))
				}
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l3endpoint",
		selectors: []string{"type:" + L3EndpointTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			// We do some length checks in here - since we expect the in field to be part of an eBPF struct that
			// is always sized statically, we can avoid checking the individual entries later on.
			in.SetHidden(true, false)
			ips := in.GetSubFieldsWithTag("type:gadget_ip_addr_t")
			if len(ips) != 1 {
				return nil, fmt.Errorf("expected %d gadget_ip_addr_t field, got %d", 1, len(ips))
			}
			if ips[0].Size() != 16 {
				return nil, fmt.Errorf("expected gadget_ip_addr_t to have 16 bytes")
			}
			versions := in.GetSubFieldsWithTag("name:version")
			if len(versions) != 1 {
				return nil, fmt.Errorf("expected exactly 1 version field")
			}
			out, err := in.AddSubField("string", datasource.WithTags("l3string"))
			if err != nil {
				return nil, fmt.Errorf("adding string field: %w", err)
			}
			// Hide padding
			for _, f := range in.GetSubFieldsWithTag("name:pad") {
				f.SetHidden(true, false)
			}
			return func(entry datasource.Data) error {
				ip := ips[0].Get(entry)
				v := versions[0].Get(entry)
				if len(v) != 1 {
					return nil
				}
				var err error
				switch v[0] {
				case 4:
					err = out.Set(entry, []byte(net.IP(ip[:4]).String()))
				case 6:
					err = out.Set(entry, []byte(net.IP(ip).String()))
				default:
					return fmt.Errorf("invalid IP version for l3endpoint")
				}
				return err
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l4endpoint",
		selectors: []string{"type:" + L4EndpointTypeName},
		replace: func(ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			// We do some length checks in here - since we expect the in field to be part of an eBPF struct that
			// is always sized statically, we can avoid checking the individual entries later on.
			in.SetHidden(true, false)
			// Get accessors to required fields
			ports := in.GetSubFieldsWithTag("name:port")
			if len(ports) != 1 {
				return nil, fmt.Errorf("expected exactly 1 port field")
			}
			if ports[0].Size() != 2 {
				return nil, fmt.Errorf("port size expected to be 2 bytes")
			}
			l3 := in.GetSubFieldsWithTag("type:" + L3EndpointTypeName)
			if len(l3) != 1 {
				return nil, fmt.Errorf("expected exactly 1 l3endpoint field")
			}
			l3strings := l3[0].GetSubFieldsWithTag("l3string")
			if len(l3strings) != 1 {
				return nil, fmt.Errorf("expected exactly 1 l3string field")
			}

			// Hide l3 & subfields of l3
			l3[0].SetHidden(true, true)
			out, err := in.AddSubField("address")
			if err != nil {
				return nil, fmt.Errorf("adding string field: %w", err)
			}
			return func(entry datasource.Data) error {
				port := binary.BigEndian.Uint16(ports[0].Get(entry))
				out.Set(entry, []byte(fmt.Sprintf("%s:%d", string(l3strings[0].Get(entry)), port)))
				return nil
			}, nil
		},
		priority: 1,
	},
}

func (f *formattersOperator) Priority() int {
	return 0
}

type formattersOperatorInstance struct {
	converters map[datasource.DataSource][]converter
}

func (f *formattersOperatorInstance) Name() string {
	return "formatters"
}

func (f *formattersOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, converters := range f.converters {
		for _, c := range converters {
			conv := c
			ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
				return conv.replacer(data)
			}, conv.priority)
		}
	}
	return nil
}

func (f *formattersOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (f *formattersOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&formattersOperator{})
}
