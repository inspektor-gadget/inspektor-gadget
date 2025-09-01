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
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

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
	// Params
	symbolizersParam         = "symbolizers"
	debuginfodCachePathParam = "debuginfod-client-cache-path"
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
	return api.Params{
		&api.Param{
			Key:          symbolizersParam,
			Description:  `Symbolizers to use. Possible values are: "none", "auto", or comma-separated list among: "symtab", "debuginfod-client-cache", "debuginfod-client-cache-on-ig-server".`,
			DefaultValue: "auto",
		},
		&api.Param{
			Key:          debuginfodCachePathParam,
			Description:  `Path to the debuginfod client cache directory. If not set, the default system cache directory is used.`,
			DefaultValue: "",
		},
	}
}

func (o *Operator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	instance := &OperatorInstance{
		subscriptions: make(map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error),
	}

	opts := symbolizer.SymbolizerOptions{
		DebuginfodCachePath: instanceParamValues[debuginfodCachePathParam],
	}
	symbolizers := instanceParamValues[symbolizersParam]
	switch symbolizers {
	case "", "none":
		// Nothing to do
	case "auto":
		opts.UseSymtab = !gadgetCtx.IsClient()
	default:
		list := strings.Split(symbolizers, ",")
		for _, s := range list {
			switch s {
			case "symtab":
				opts.UseSymtab = !gadgetCtx.IsClient()
			case "debuginfod-client-cache":
				if !gadgetCtx.IsRemoteCall() {
					opts.UseDebugInfodClientCache = true
				}
			case "debuginfod-client-cache-on-ig-server":
				if gadgetCtx.IsRemoteCall() {
					opts.UseDebugInfodClientCache = true
				}
			default:
				return nil, fmt.Errorf("invalid symbolizer: %s", s)
			}
		}
	}

	var err error
	// When the Symbolizer implements more options, they can be added here
	if opts.UseSymtab || opts.UseDebugInfodClientCache {
		// Use a sync.OnceValue to delay the creation of the Symbolizer because:
		// - otherwise it is needlessly created during GetGadgetInfo
		instance.symbolizer = sync.OnceValue(func() *symbolizer.Symbolizer {
			s, err := symbolizer.NewSymbolizer(opts)
			if err != nil {
				log.Errorf("creating symbolizer: %s", err)
				return nil
			}
			return s
		})
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
	buildIDMap   *ebpf.Map
	symbolizer   func() *symbolizer.Symbolizer

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

			// The ustack operator can run both on the client and on the server side.
			// If it runs on the client side, the server might have already added the subfields.
			var addressesField, buildIDField, symbolsField datasource.FieldAccessor
			var err error

			if addressesFieldAll := in.GetSubFieldsWithTag("name:addresses"); len(addressesFieldAll) == 0 {
				addressesField, err = in.AddSubField("addresses", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden), datasource.WithTags("name:addresses", "operator:ustack"))
				if err != nil {
					return err
				}
			} else {
				addressesField = addressesFieldAll[0]
				if !addressesField.HasAllTagsOf("operator:ustack") {
					logger.Warn("field addresses exists but does not belong to the ustack operator")
					continue
				}

			}

			if buildIDFieldAll := in.GetSubFieldsWithTag("name:buildid"); len(buildIDFieldAll) == 0 {
				buildIDField, err = in.AddSubField("buildid", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden), datasource.WithTags("name:buildid", "operator:ustack"))
				if err != nil {
					return err
				}
			} else {
				buildIDField = buildIDFieldAll[0]
				if !buildIDField.HasAllTagsOf("operator:ustack") {
					logger.Warn("field buildid exists but does not belong to the ustack operator")
					continue
				}
			}

			if symbolsFieldAll := in.GetSubFieldsWithTag("name:symbols"); len(symbolsFieldAll) == 0 {
				symbolsField, err = in.AddSubField("symbols", api.Kind_String, datasource.WithFlags(datasource.FieldFlagHidden), datasource.WithTags("name:symbols", "operator:ustack"))
				if err != nil {
					return err
				}
			} else {
				symbolsField = symbolsFieldAll[0]
				if !symbolsField.HasAllTagsOf("operator:ustack") {
					logger.Warn("field symbols exists but does not belong to the ustack operator")
					continue
				}
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

				stackQueries := make([]symbolizer.StackItemQuery, 0, ebpftypes.UserPerfMaxStackDepth)
				var alreadyKnownSymbols []string // symbols already resolved server-side

				// The ustack operator can run both on the client and on the server side.
				// The BPF map is not available client-side (e.g. kubectl-gadget)
				if o.userStackMap != nil {
					addressesStr, buildIDStr, moreStackItems, err := readUserStackMap(gadgetCtx, o.userStackMap, o.buildIDMap, stackId)
					if err != nil {
						logger.Warn(err)
						return nil
					}
					if addressesStr != "" {
						addressesField.PutString(data, addressesStr)
					}
					if buildIDStr != "" {
						buildIDField.PutString(data, buildIDStr)
					}
					stackQueries = append(stackQueries, moreStackItems...)
					alreadyKnownSymbols = make([]string, len(stackQueries))
				} else {
					// The symbolizer might be used client-side where we don't
					// have access to BPF maps. Access data from the data source
					// instead.
					addressesStr, _ := addressesField.String(data)
					addressesList := strings.Split(addressesStr, "; ")
					buildIDStr, _ := buildIDField.String(data)
					buildidList := strings.Split(buildIDStr, "; ")
					alreadyKnownSymbolsStr, _ := symbolsField.String(data)
					alreadyKnownSymbols = strings.Split(alreadyKnownSymbolsStr, "; ")
					for i := range alreadyKnownSymbols {
						index := strings.IndexByte(alreadyKnownSymbols[i], ']')
						if index >= 0 {
							alreadyKnownSymbols[i] = alreadyKnownSymbols[i][index+1:]
						}
					}

					for i := range addressesList {
						if addressesList[i] == "" {
							break
						}
						if len(buildidList) <= i {
							buildidList = append(buildidList, "")
						}
						if len(alreadyKnownSymbols) <= i {
							alreadyKnownSymbols = append(alreadyKnownSymbols, "")
						}

						var idx int
						var addr uint64
						var buildidStr string
						var buildid [20]byte
						var validBuildID bool
						var offset uint64
						var ip uint64
						_, err := fmt.Sscanf(addressesList[i], "[%d]0x%x", &idx, &addr)
						if err != nil {
							break
						}
						_, err = fmt.Sscanf(buildidList[i], "[%d]%s +%x", &idx, &buildidStr, &offset)
						if err != nil {
							_, _ = fmt.Sscanf(buildidList[i], "[%d]%x", &idx, &ip)
							// It's ok if we don't have a build ID.
						} else {
							validBuildID = true
						}
						buildidSlice, err := hex.DecodeString(buildidStr)
						if err != nil {
							logger.Warnf("decoding build ID %q: %s", buildidStr, err)
							break
						}
						// It's ok if we don't have a build ID. But if we have one, it should be valid.
						if len(buildidSlice) != 20 && len(buildidSlice) != 0 {
							logger.Warnf("decoding build ID %q: invalid length %d", buildidStr, len(buildidSlice))
							break
						}
						copy(buildid[:], buildidSlice)
						stackQueries = append(stackQueries, symbolizer.StackItemQuery{
							Addr:         addr,
							ValidBuildID: validBuildID,
							BuildID:      buildid,
							Offset:       offset,
							IP:           ip,
						})
					}
				}

				if o.symbolizer != nil && o.symbolizer() != nil {
					task := symbolizer.Task{
						Name:         fmt.Sprintf("%s/%s", containerName, comm),
						PidNumbers:   pidNumbers,
						ContainerPid: containerPid,
						Ino:          inode,
						MtimeSec:     int64(mtimeSec),
						MtimeNsec:    mtimeNsec,
					}
					stackQueriesResponse, err := o.symbolizer().Resolve(task, stackQueries)
					if err != nil {
						logger.Warnf("symbolizer: %s", err)
						return nil
					}

					var symbolsBuilder strings.Builder
					for i, res := range stackQueriesResponse {
						s := res.Symbol
						if !res.Found && i < len(alreadyKnownSymbols) {
							s = alreadyKnownSymbols[i]
						}
						fmt.Fprintf(&symbolsBuilder, "[%d]%s; ", i, s)
					}
					symbolsField.PutString(data, symbolsBuilder.String())
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

func (o *OperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	if !gadgetCtx.IsClient() {
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

		buildIDMapAny, ok := gadgetCtx.GetVar(operators.MapPrefix + ebpftypes.BuildIdMapName)
		// buildIDMap is optional. Older gadgets won't have it.
		if ok {
			o.buildIDMap, ok = buildIDMapAny.(*ebpf.Map)
			if !ok {
				return errors.New("build_id map is not of expected type")
			}
		}
	}

	for ds, funcs := range o.subscriptions {
		for _, f := range funcs {
			ds.Subscribe(f, Priority)
		}
	}
	return nil
}

func (o *OperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *OperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	if o.symbolizer != nil && o.symbolizer() != nil {
		o.symbolizer().Close()
	}
	return nil
}

func init() {
	operators.RegisterDataOperator(&Operator{})
}
