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
	"errors"
	"fmt"
	"io/fs"
	"math/bits"
	"strings"
	"syscall"
	"time"

	"github.com/dustin/go-humanize"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/annotations"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/protocols"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
)

const (
	timestampTargetAnnotation = "formatters.timestamp.target"
	syscallTargetAnnotation   = "formatters.syscall.target"
	signalTargetAnnotation    = "formatters.signal.target"
	errnoTargetAnnotation     = "formatters.errno.target"
	bytesTargetAnnotation     = "formatters.bytes.target"
	durationTargetAnnotation  = "formatters.duration.target"
	fileModeTargetAnnotation  = "formatters.file_mode.target"
	fileFlagsTargetAnnotation = "formatters.file_flags.target"
	Priority                  = 0
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
	ips := in.GetSubFieldsWithTag("type:" + ebpftypes.IPAddrTypeName)
	if len(ips) != 1 {
		return nil, fmt.Errorf("expected %d %q field, got %d", 1, ebpftypes.IPAddrTypeName, len(ips))
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

	annotations.SetFieldVisibility(false, in)

	return func(entry datasource.Data) (string, error) {
		addrStr, err := common.GetIPForVersion(entry, versions[0], ips[0])
		if err != nil {
			return "", fmt.Errorf("getting IP address: %w", err)
		}

		addrF.PutString(entry, addrStr)
		return addrStr, nil
	}, nil
}

func formatDuration(d time.Duration) string {
	switch {
	case d < time.Microsecond:
		return fmt.Sprintf("%dns", d.Nanoseconds())
	case d < time.Millisecond:
		return fmt.Sprintf("%.2fµs", float64(d)/float64(time.Microsecond))
	case d < time.Second:
		return fmt.Sprintf("%.2fms", float64(d)/float64(time.Millisecond))
	default:
		return d.String()
	}
}

// Standard Linux file open flags from <fcntl.h>
const (
	// Access modes (handled separately)
	O_RDONLY  = 0
	O_WRONLY  = 1
	O_RDWR    = 2
	O_ACCMODE = 3

	// Bit flags
	O_CREAT     = 0o100
	O_EXCL      = 0o200
	O_NOCTTY    = 0o400
	O_TRUNC     = 0o1000
	O_APPEND    = 0o2000
	O_NONBLOCK  = 0o4000
	O_DSYNC     = 0o10000
	O_FASYNC    = 0o20000
	O_DIRECT    = 0o40000
	O_LARGEFILE = 0o100000
	O_DIRECTORY = 0o200000
	O_NOFOLLOW  = 0o400000
	O_NOATIME   = 0o1000000
	O_CLOEXEC   = 0o2000000
)

// flagMap pairs the bitmask of a flag with its string representation.
// Using a slice of structs makes the relationship explicit and order-independent.
var flagMap = []struct {
	val  int32
	name string
}{
	{O_CREAT, "O_CREAT"},
	{O_EXCL, "O_EXCL"},
	{O_NOCTTY, "O_NOCTTY"},
	{O_TRUNC, "O_TRUNC"},
	{O_APPEND, "O_APPEND"},
	{O_NONBLOCK, "O_NONBLOCK"},
	{O_DSYNC, "O_DSYNC"},
	{O_FASYNC, "O_FASYNC"},
	{O_DIRECT, "O_DIRECT"},
	{O_LARGEFILE, "O_LARGEFILE"},
	{O_DIRECTORY, "O_DIRECTORY"},
	{O_NOFOLLOW, "O_NOFOLLOW"},
	{O_NOATIME, "O_NOATIME"},
	{O_CLOEXEC, "O_CLOEXEC"},
}

func decodeFlags(flags int32) []string {
	// Pre-allocate a slice with a reasonable capacity to avoid reallocations.
	// The number of set bits gives an exact count.
	capacity := bits.OnesCount32(uint32(flags))
	out := make([]string, 0, capacity)

	// Handle the access mode, which is not a bitmask.
	switch flags & O_ACCMODE {
	case O_RDONLY:
		out = append(out, "O_RDONLY")
	case O_WRONLY:
		out = append(out, "O_WRONLY")
	case O_RDWR:
		out = append(out, "O_RDWR")
	}

	// Check each flag by its actual value.
	for _, f := range flagMap {
		if (flags & f.val) == f.val {
			out = append(out, f.name)
		}
	}

	return out
}

// careful: order and priority matter both!
var replacers = []replacer{
	{
		name:      "signal",
		selectors: []string{"type:" + ebpftypes.SignalTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.signal", in, signalTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					metadatav1.ValueOneOfAnnotation: strings.Join(signalNames, ", "),
				}),
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			signalField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				inBytes := in.Get(data)
				switch len(inBytes) {
				default:
					return nil
				case 4:
					signalNumber, _ := in.Uint32(data)
					signalName := unix.SignalName(syscall.Signal(signalNumber))
					if signalName == "" {
						signalName = fmt.Sprintf("signal#%d", signalNumber)
					}
					signalField.Set(data, []byte(signalName))
				}
				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "errno",
		selectors: []string{"type:" + ebpftypes.ErrnoTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.errno", in, errnoTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					metadatav1.TemplateAnnotation:   "errorString",
					metadatav1.ValueOneOfAnnotation: strings.Join(errnoNames, ", "),
				}),
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			errnoField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

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
		selectors: []string{"type:" + ebpftypes.SyscallTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			if in.Type() != api.Kind_Uint64 {
				return nil, fmt.Errorf("checking field %q: expected uint64", in.Name())
			}

			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.syscall", in, syscallTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			syscallField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

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
		selectors: []string{"type:" + ebpftypes.TimestampTypeName},
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
					metadatav1.TemplateAnnotation: "timestamp",
				}),
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			out, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				inBytes := in.Get(data)
				switch len(inBytes) {
				default:
					return nil
				case 8:
					var errs []error

					// TODO: WallTimeFromBootTime() converts too much for this, create a new func that does less
					correctedTime := gadgets.WallTimeFromBootTime(ds.ByteOrder().Uint64(inBytes))
					ds.ByteOrder().PutUint64(inBytes, uint64(correctedTime))
					t := time.Unix(0, int64(correctedTime))
					errs = append(errs, out.Set(data, []byte(t.Format(timestampFormat))))
					errs = append(errs, in.PutUint64(data, uint64(correctedTime)))

					return errors.Join(errs...)
				}
			}, nil
		},
		priority: 0,
	},
	{
		name:      "bytes",
		selectors: []string{"type:" + ebpftypes.BytesTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.bytes", in, bytesTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					metadatav1.TemplateAnnotation: "bytes",
				}),
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}

			bytesField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				switch in.Type() {
				case api.Kind_Uint64:
					bytesValue, err := in.Uint64(data)
					if err != nil {
						return err
					}

					humanReadable := humanize.Bytes(bytesValue)
					bytesField.PutString(data, humanReadable)
				}
				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "duration",
		selectors: []string{"type:" + ebpftypes.DurationTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.duration", in, durationTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithAnnotations(map[string]string{
					metadatav1.TemplateAnnotation: "duration",
				}),
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}

			durationField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				switch in.Type() {
				case api.Kind_Uint64:
					durationValue, err := in.Uint64(data)
					if err != nil {
						return err
					}

					humanReadable := formatDuration(time.Duration(durationValue))
					durationField.PutString(data, humanReadable)
				}
				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "l3endpoint",
		selectors: []string{"type:" + ebpftypes.L3EndpointTypeName},
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
		selectors: []string{"type:" + ebpftypes.L4EndpointTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			l3Replace, err := handleL3Endpoint(in)
			if err != nil {
				return nil, err
			}

			ports := in.GetSubFieldsWithTag("name:port")
			if len(ports) != 1 {
				return nil, fmt.Errorf("expected exactly 1 port field")
			}

			protos := in.GetSubFieldsWithTag("name:proto_raw")
			var protoField datasource.FieldAccessor
			var protoFieldName string

			if len(protos) == 1 {
				protoFieldName = strings.TrimSuffix(protos[0].Name(), "_raw")
				protoField, err = in.AddSubField(protoFieldName, api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
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
				datasource.WithTags("endpoint"),
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

				port, err := ports[0].Uint16(entry)
				if err != nil {
					return fmt.Errorf("getting port: %w", err)
				}
				endpointF.PutString(entry, fmt.Sprintf("%s:%d", addrStr, port))

				if len(protos) == 1 {
					protoNumber, err := protos[0].Uint16(entry)
					if err != nil {
						return fmt.Errorf("getting proto: %w", err)
					}
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
	{
		name:      "file_mode",
		selectors: []string{"type:" + ebpftypes.FileModeTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			if in.Type() != api.Kind_Uint32 {
				return nil, fmt.Errorf("checking field %q: expected uint32", in.Name())
			}

			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.file_mode", in, fileModeTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			fileModeField, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				mode, err := in.Uint32(data)
				if err != nil {
					return err
				}

				fileModeField.PutString(data, fs.FileMode(mode).String())

				return nil
			}, nil
		},
		priority: 0,
	},
	{
		name:      "file_flags",
		selectors: []string{"type:" + ebpftypes.FileFlagsTypeName},
		replace: func(logger logger.Logger, ds datasource.DataSource, in datasource.FieldAccessor) (func(data datasource.Data) error, error) {
			if in.Type() != api.Kind_Uint32 {
				return nil, fmt.Errorf("checking field %q: expected uint32", in.Name())
			}

			outName, err := annotations.GetTargetNameFromAnnotation(logger, "formatters.file_flags", in, fileFlagsTargetAnnotation)
			if err != nil {
				return nil, err
			}

			opts := []datasource.FieldOption{
				datasource.WithSameParentAs(in),
				datasource.WithSameOrderAs(in),
			}
			fileFlagsFields, err := ds.AddField(outName, api.Kind_String, opts...)
			if err != nil {
				return nil, err
			}

			annotations.SetFieldVisibility(true, in)

			return func(data datasource.Data) error {
				mode, err := in.Int32(data)
				if err != nil {
					return err
				}

				flags := decodeFlags(mode)
				// TODO: the datasource doesn't support arrays yet.
				flagsStr := strings.Join(flags, "|")
				fileFlagsFields.PutString(data, flagsStr)

				return nil
			}, nil
		},
		priority: 0,
	},
}

func (f *formattersOperator) Priority() int {
	return Priority
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

func (f *formattersOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

func init() {
	operators.RegisterDataOperator(&formattersOperator{})
}

var FormattersOperator = &formattersOperator{}
