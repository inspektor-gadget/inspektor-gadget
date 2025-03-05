// Copyright 2025 The Inspektor Gadget authors
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

// Package ustack provides a data operator that resolves user stack traces.
package ustack

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
)

const (
	Name     = "ustack"
	Priority = 100
)

const (
	// Annotations
	userStackTargetNameAnnotation = "ebpf.formatter.ustack"

	// Params
	symbolizersParam = "symbolizers"
)

type Operator struct{}

func (o *Operator) Name() string {
	return Name
}

func (o *Operator) Init(params *params.Params) error {
	return nil
}

func (o *Operator) GlobalParams() api.Params {
	return nil
}

func (o *Operator) InstanceParams() api.Params {
	return api.Params{&api.Param{
		Key:          symbolizersParam,
		Description:  `Symbolizers to use. Possible values are: "none", "auto", or comma-separated list among: "symtab"`,
		DefaultValue: "auto",
	}}
}

func (o *Operator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	instance := &OperatorInstance{
		subscriptions: make(map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error),
	}

	opts := symbolizer.SymbolizerOptions{}
	symbolizers := instanceParamValues[symbolizersParam]
	switch symbolizers {
	case "none":
		opts.UseSymtab = false
	case "auto":
		opts.UseSymtab = true
	default:
		list := strings.Split(symbolizers, ",")
		for _, s := range list {
			switch s {
			case "symtab":
				opts.UseSymtab = true
			default:
				return nil, fmt.Errorf("invalid symbolizer: %s", s)
			}
		}
	}

	var err error
	if symbolizers != "none" {
		instance.symbolizer, err = symbolizer.NewSymbolizer(opts)
		if err != nil {
			return nil, err
		}
	}
	err = instance.init(gadgetCtx)
	if err != nil {
		return nil, err
	}
	if len(instance.subscriptions) == 0 {
		return nil, nil
	}
	return instance, nil
}

func (o *Operator) Priority() int {
	return Priority
}

type OperatorInstance struct {
	userStackMap *ebpf.Map
	symbolizer   *symbolizer.Symbolizer

	subscriptions map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error
}

func (o *OperatorInstance) init(gadgetCtx operators.GadgetContext) error {
	logger := gadgetCtx.Logger()

	for _, ds := range gadgetCtx.GetDataSources() {
		for _, in := range ds.GetFieldsWithTag("type:" + ebpftypes.UserStackTypeName) {
			if in == nil {
				continue
			}
			in.SetHidden(true, true)

			// Optional fields: don't error out if nil
			containerPidField := ds.GetField("runtime.containerPid")
			containerNameField := ds.GetField("runtime.containerName")
			commField := ds.GetField("proc.comm")

			pidLevel0Field := in.GetSubFieldsWithTag("name:pid_level0")
			if len(pidLevel0Field) != 1 {
				logger.Warn("no pid (level 0) field found")
				continue
			}
			pidnsLevel0Field := in.GetSubFieldsWithTag("name:pidns_level0")
			if len(pidnsLevel0Field) != 1 {
				logger.Warn("no pidns (level 0) field found")
				continue
			}
			pidLevel1Field := in.GetSubFieldsWithTag("name:pid_level1")
			if len(pidLevel1Field) != 1 {
				logger.Warn("no pid (level 1) field found")
				continue
			}
			pidnsLevel1Field := in.GetSubFieldsWithTag("name:pidns_level1")
			if len(pidnsLevel1Field) != 1 {
				logger.Warn("no pidns (level 1) field found")
				continue
			}

			stackField := in.GetSubFieldsWithTag("name:stack_id")
			if len(stackField) != 1 {
				logger.Warn("no stack_id field found")
				continue
			}

			inodeField := in.GetSubFieldsWithTag("name:exe_inode")
			if len(inodeField) != 1 {
				logger.Warn("no inode field found")
				continue
			}
			mtimeSecField := in.GetSubFieldsWithTag("name:mtime_sec")
			if len(mtimeSecField) != 1 {
				logger.Warn("no mtime_sec field found")
				continue
			}
			mtimeNsecField := in.GetSubFieldsWithTag("name:mtime_nsec")
			if len(mtimeNsecField) != 1 {
				logger.Warn("no mtime_nsec field found")
				continue
			}

			addressesField, err := in.AddSubField("addresses", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
			if err != nil {
				return err
			}
			symbolsField, err := in.AddSubField("symbols", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden))
			if err != nil {
				return err
			}

			converter := func(ds datasource.DataSource, data datasource.Data) error {
				inode, _ := inodeField[0].Uint64(data)
				// If user stacks are disabled
				if inode == 0 {
					return nil
				}

				stackId, _ := stackField[0].Uint32(data)
				pidLevel0, _ := pidLevel0Field[0].Uint32(data)
				pidnsLevel0, _ := pidnsLevel0Field[0].Uint32(data)
				pidLevel1, _ := pidLevel1Field[0].Uint32(data)
				pidnsLevel1, _ := pidnsLevel1Field[0].Uint32(data)
				if pidLevel0 == 0 {
					logger.Warn("user stack with invalid pid")
					return nil
				}
				if pidnsLevel0 == 0 {
					logger.Warn("user stack with invalid pidns")
					return nil
				}
				pidNumbers := []symbolizer.PidNumbers{
					{
						Pid:     pidLevel0,
						PidNsId: pidnsLevel0,
					},
				}
				if pidLevel1 != 0 && pidnsLevel1 != 0 {
					pidNumbers = append(pidNumbers, symbolizer.PidNumbers{
						Pid:     pidLevel1,
						PidNsId: pidnsLevel1,
					})
				}
				containerPid := uint32(0)
				if containerPidField != nil {
					containerPid, _ = containerPidField.Uint32(data)
				}
				containerName := ""
				if containerNameField != nil {
					containerName, _ = containerNameField.String(data)
				}
				comm := ""
				if commField != nil {
					comm, _ = commField.String(data)
				}
				mtimeSec, _ := mtimeSecField[0].Uint64(data)
				mtimeNsec, _ := mtimeNsecField[0].Uint32(data)

				stack := [ebpftypes.UserPerfMaxStackDepth]uint64{}
				err := o.userStackMap.Lookup(stackId, &stack)
				if err != nil {
					logger.Warnf("stack with ID %d is lost: %s", stackId, err.Error())
					return nil
				}

				addressesString := ""
				addrs := make([]uint64, 0, len(stack))
				for i, addr := range stack {
					if addr == 0 {
						break
					}
					addrs = append(addrs, addr)
					addressesString += fmt.Sprintf("[%d]0x%016x; ", i, addr)
				}
				addressesField.PutString(data, addressesString)

				if o.symbolizer != nil {
					task := symbolizer.Task{
						Name:         fmt.Sprintf("%s/%s", containerName, comm),
						PidNumbers:   pidNumbers,
						ContainerPid: containerPid,
						Ino:          inode,
						MtimeSec:     int64(mtimeSec),
						MtimeNsec:    mtimeNsec,
					}
					symbols, err := o.symbolizer.Resolve(task, addrs)
					if err != nil {
						logger.Warnf("symbolizer: %s", err)
						return nil
					}

					outString := ""
					for i, symbol := range symbols {
						outString += fmt.Sprintf("[%d]%s; ", i, symbol)
					}
					symbolsField.PutString(data, outString)
				}
				return nil
			}
			o.subscriptions[ds] = append(o.subscriptions[ds], converter)
		}
	}
	return nil
}

func (o *OperatorInstance) Name() string {
	return Name
}

func (o *OperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if o.symbolizer != nil {
		o.symbolizer.Close()
	}
	return nil
}

func (o *OperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	userStackMapAny, ok := gadgetCtx.GetVar(operators.MapPrefix + ebpftypes.UserStackMapName)
	if !ok || userStackMapAny == nil {
		return errors.New("user stack map is not initialized but used. " +
			"if you are using `gadget_user_stack` as event field, " +
			"try to include <gadget/user_stack_map.h>")
	}
	o.userStackMap, ok = userStackMapAny.(*ebpf.Map)
	if !ok {
		return errors.New("user stack map is not of expected type")
	}
	if o.userStackMap == nil {
		return errors.New("user stack map is nil")
	}

	for ds, funcs := range o.subscriptions {
		for _, f := range funcs {
			ds.Subscribe(f, Priority)
		}
	}
	return nil
}

func init() {
	operators.RegisterDataOperator(&Operator{})
}
