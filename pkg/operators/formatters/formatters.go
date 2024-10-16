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
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/go-multierror"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/annotations"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/protocols"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
)

// Keep this aligned with include/gadget/types.h
const (
	// L3EndpointTypeName contains the name of the type that gadgets should use to store an L3 endpoint.
	L3EndpointTypeName = "gadget_l3endpoint_t"

	// L4EndpointTypeName contains the name of the type that gadgets should use to store an L4 endpoint.
	L4EndpointTypeName = "gadget_l4endpoint_t"

	// IPAddrTypeName contains the name of the type that gadgets should use to store an IP address.
	IPAddrTypeName = "gadget_ip_addr_t"

	// TimestampTypeName contains the name of the type to store a timestamp
	TimestampTypeName = "gadget_timestamp"

	// Name of the type to store a signal
	SignalTypeName = "gadget_signal"

	// ErrnoTypeName contains the name of the type to store an errno
	ErrnoTypeName = "gadget_errno"

	// Name of the type to store a syscall
	SyscallTypeName = "gadget_syscall"
)

const (
	timestampTargetAnnotation = "formatters.timestamp.target"
	syscallTargetAnnotation   = "formatters.syscall.target"
	signalTargetAnnotation    = "formatters.signal.target"
	errnoTargetAnnotation     = "formatters.errno.target"
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
				replFunc, err := r.replace(logger, ds, field)
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
	replace func(logger.Logger, datasource.DataSource, datasource.FieldAccessor) (func(datasource.Data) error, error)

	// priority to be used when subscribing to the DataSource
	priority int
}

func handleL3Endpoint(in datasource.FieldAccessor) (func(entry datasource.Data) (string, error), error) {
	// We do some length checks in here - since we expect the in field to be part of an eBPF struct that
	// is always sized statically, we can avoid checking the individual entries later on.
	ips := in.GetSubFieldsWithTag("type:" + IPAddrTypeName)
	if len(ips) != 1 {
		return nil, fmt.Errorf("expected %d %q field, got %d", 1, IPAddrTypeName, len(ips))
	}
	if ips[0].Size() != 16 {
		return nil, fmt.Errorf("expected %q to have 16 bytes, got %d", IPAddrTypeName, ips[0].Size())
	}
	ips[0].RemoveReference(true)

	versions := in.GetSubFieldsWithTag("name:version")
	if len(versions) != 1 {
		return nil, fmt.Errorf("expected exactly 1 version field")
	}

	// Pretty L3 address
	addrName := strings.TrimSuffix(ips[0].Name(), "_raw")
	addrF, err := in.AddSubField(addrName, api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding address field: %w", err)
	}

	in.AddAnnotation(datasource.ColumnsReplaceAnnotation, addrF.FullName())

	// Hide all subfields
	in.SetHidden(true, true)
	// Show only root field that will contain the pretty address
	in.SetHidden(false, false)

	return func(entry datasource.Data) (string, error) {
		ip := ips[0].Get(entry)
		v, err := versions[0].Uint8(entry)
		if err != nil {
			return "", err
		}

		var addrStr string
		switch v {
		case 4:
			addrStr = net.IP(ip[:4]).String()
		case 6:
			addrStr = net.IP(ip).String()
		default:
			return "", fmt.Errorf("invalid IP version %d for l4endpoint", v)
		}

		addrF.PutString(entry, addrStr)
		return addrStr, nil
	}, nil
}

// careful: order and priority matter both!
var replacers = []replacer{
	{
		name:      "signal",
		selectors: []string{"type:" + SignalTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.signal", in, signalTargetAnnotation)
			if err != nil {
				return nil, err
			}

			signalField, err := ds.AddField(outName, api.Kind_String, datasource.WithSameParentAs(in))
			if err != nil {
				return nil, err
			}

			in.SetHidden(true, false)

			return func(data datasource.Data) error {
				inBytes := in.Get(data)
				switch len(inBytes) {
				default:
					return nil
				case 4:
					signalNumber, _ := in.Uint32(data)
					signalName := unix.SignalName(syscall.Signal(signalNumber))
					signalField.Set(data, []byte(signalName))
				}
				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "errno",
		selectors: []string{"type:" + ErrnoTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.errno", in, errnoTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					datasource.TemplateAnnotation: "errorString",
				}),
				datasource.WithSameParentAs(in),
			}
			errnoField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			in.SetHidden(true, false)

			return func(data datasource.Data) error {
				switch in.Type() {
				case api.Kind_Uint32:
					errnoNumber, _ := in.Uint32(data)
					errnoName := unix.ErrnoName(syscall.Errno(errnoNumber))
					if errnoNumber != 0 && errnoName == "" {
						errnoName = fmt.Sprintf("error#%d", errnoNumber)
					}
					errnoField.PutString(data, errnoName)
				}
				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "syscall",
		selectors: []string{"type:" + SyscallTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			if in.Type() != api.Kind_Uint64 {
				return nil, fmt.Errorf("checking field %q: expected uint64", in.Name())
			}

			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.syscall", in, syscallTargetAnnotation)
			if err != nil {
				return nil, err
			}
			syscallField, err := ds.AddField(outName, api.Kind_String, datasource.WithSameParentAs(in))
			if err != nil {
				return nil, err
			}

			in.SetHidden(true, false)

			return func(data datasource.Data) error {
				syscallNumber, err := in.Uint64(data)
				if err != nil {
					return err
				}

				syscallName, exist := syscalls.GetSyscallNameByNumber(int(syscallNumber))
				if !exist {
					syscallName = "unknown"
				}
				syscallField.PutString(data, "SYS_"+strings.ToUpper(syscallName))

				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "timestamp",
		selectors: []string{"type:" + TimestampTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			timestampFormat := "2006-01-02T15:04:05.000000000Z07:00"
			if format := in.Annotations()["formatters.timestamp.format"]; format != "" {
				logger.Debugf("formatter.timestamp: using custom timestamp format %q for field %q", format, in.Name())
				timestampFormat = format
			}

			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.timestamp", in, timestampTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					datasource.TemplateAnnotation: "timestamp",
				}),
				datasource.WithSameParentAs(in),
			}
			out, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			in.SetHidden(true, false)

			return func(data datasource.Data) error {
				inBytes := in.Get(data)
				switch len(inBytes) {
				default:
					return nil
				case 8:
					var result error

					// TODO: WallTimeFromBootTime() converts too much for this, create a new func that does less
					correctedTime := gadgets.WallTimeFromBootTime(ds.ByteOrder().Uint64(inBytes))
					ds.ByteOrder().PutUint64(inBytes, uint64(correctedTime))
					t := time.Unix(0, int64(correctedTime))
					if err := out.Set(data, []byte(t.Format(timestampFormat))); err != nil {
						multierror.Append(result, err)
					}
					if err := in.PutUint64(data, uint64(correctedTime)); err != nil {
						multierror.Append(result, err)
					}

					return result
				}
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l3endpoint",
		selectors: []string{"type:" + L3EndpointTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			replace, err := handleL3Endpoint(in)
			if err != nil {
				return nil, err
			}

			return func(entry datasource.Data) error {
				_, err := replace(entry)
				return err
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l4endpoint",
		selectors: []string{"type:" + L4EndpointTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			l3Replace, err := handleL3Endpoint(in)
			if err != nil {
				return nil, err
			}

			ports := in.GetSubFieldsWithTag("name:port")
			if len(ports) != 1 {
				return nil, fmt.Errorf("expected exactly 1 port field")
			}
			if ports[0].Size() != 2 {
				return nil, fmt.Errorf("port size expected to be 2 bytes")
			}

			protos := in.GetSubFieldsWithTag("name:proto_raw")
			var protoField datasource.FieldAccessor
			var protoFieldName string

			if len(protos) == 1 {
				if protos[0].Size() != 2 {
					return nil, fmt.Errorf("proto size expected to be 2 bytes")
				}
				protoFieldName = strings.TrimSuffix(protos[0].Name(), "_raw")
				protoField, err = in.AddSubField(protoFieldName, api.Kind_String)
				if err != nil {
					return nil, err
				}
			} else if len(protos) > 1 {
				return nil, fmt.Errorf("expected at most 1 proto_raw field, found %d", len(protos))
			}

			endpointF, err := in.AddSubField("endpoint", api.Kind_String,
				datasource.WithAnnotations(map[string]string{
					json.SkipFieldAnnotation: "true",
				}),
				datasource.WithFlags(datasource.FieldFlagHidden),
			)
			if err != nil {
				return nil, fmt.Errorf("adding endpoint field: %w", err)
			}

			in.AddAnnotation(datasource.ColumnsReplaceAnnotation, endpointF.FullName())

			return func(entry datasource.Data) error {
				addrStr, err := l3Replace(entry)
				if err != nil {
					return err
				}

				port, _ := ports[0].Uint16(entry)
				endpointF.PutString(entry, fmt.Sprintf("%s:%d", addrStr, port))

				if len(protos) == 1 {
					protoNumber, _ := protos[0].Uint16(entry)
					protoName, exist := protocols.GetProtocolNameByNumber(int(protoNumber))
					if !exist {
						protoName = fmt.Sprintf("proto#%d", protoNumber)
					}
					protoField.PutString(entry, protoName)
				}
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

var FormattersOperator = &formattersOperator{}
