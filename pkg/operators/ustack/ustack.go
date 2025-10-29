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
	"sync"

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
	// Params
	symbolizersParam         = "symbolizers"
	debuginfodCachePathParam = "debuginfod-cache-path"
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
			Description:  `Symbolizers to use. Possible values are: "none", "auto", or comma-separated list among: "symtab", "debuginfod-cache", "debuginfod-cache-on-ig-server".`,
			DefaultValue: "auto",
		},
		&api.Param{
			Key:          debuginfodCachePathParam,
			Description:  `Path to the debuginfod cache directory. If not set, the default system cache directory is used.`,
			DefaultValue: "",
		},
	}
}

func (o *Operator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, instanceParamValues api.ParamValues) (operators.DataOperatorInstance, error) {
	instance := &OperatorInstance{
		subscriptions: make(map[datasource.DataSource][]func(ds datasource.DataSource, data datasource.Data) error),
		symbolizerOpts: symbolizer.SymbolizerOptions{
			DebuginfodCachePath: instanceParamValues[debuginfodCachePathParam],
		},
	}

	symbolizers := instanceParamValues[symbolizersParam]
	switch symbolizers {
	case "", "none":
		// Nothing to do
	case "auto":
		instance.symbolizerOpts.UseSymtab = !gadgetCtx.IsClient()
	default:
		list := strings.Split(symbolizers, ",")
		for _, s := range list {
			switch s {
			case "symtab":
				instance.symbolizerOpts.UseSymtab = !gadgetCtx.IsClient()
			case "debuginfod-cache":
				if !gadgetCtx.IsRemoteCall() {
					instance.symbolizerOpts.UseDebugInfodCache = true
				}
			case "debuginfod-cache-on-ig-server":
				if gadgetCtx.IsRemoteCall() {
					instance.symbolizerOpts.UseDebugInfodCache = true
				}
			default:
				return nil, fmt.Errorf("invalid symbolizer: %s", s)
			}
		}
	}
	instance.symbolizerEnabled = instance.symbolizerOpts.UseSymtab || instance.symbolizerOpts.UseDebugInfodCache

	err := instance.init(gadgetCtx)
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
	userStackMap func() *ebpf.Map
	buildIDMap   func() *ebpf.Map

	symbolizerEnabled bool
	symbolizer        *symbolizer.Symbolizer
	symbolizerOpts    symbolizer.SymbolizerOptions

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

			tgidLevel0Field := in.GetSubFieldsWithTag("name:tgid_level0")
			if len(tgidLevel0Field) != 1 {
				logger.Warn("no tgid (level 0) field found")
				continue
			}
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

			majorField := in.GetSubFieldsWithTag("name:major")
			if len(majorField) != 1 {
				logger.Warn("no major field found")
				continue
			}

			minorField := in.GetSubFieldsWithTag("name:minor")
			if len(minorField) != 1 {
				logger.Warn("no minor field found")
				continue
			}

			inodeField := in.GetSubFieldsWithTag("name:inode")
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
			baseAddrHashField := in.GetSubFieldsWithTag("name:base_addr_hash")
			if len(baseAddrHashField) != 1 {
				logger.Warn("no base_addr_hash field found")
				continue
			}

			// The ustack operator can run both on the client and on the server side.
			// If it runs on the client side, the server might have already added the subfields.
			addField := func(parent datasource.FieldAccessor, name string, kind api.Kind) (datasource.FieldAccessor, error) {
				field := parent.GetSubFieldsWithTag("name:" + name)
				if len(field) == 0 {
					return parent.AddSubField(name, kind,
						datasource.WithFlags(datasource.FieldFlagHidden),
						datasource.WithTags("name:"+name, "operator:ustack"))
				}
				if !field[0].HasAllTagsOf("operator:ustack") {
					logger.Warn("field " + name + " exists but does not belong to the ustack operator")
					return nil, fmt.Errorf("field %q exists but does not belong to the ustack operator", name)
				}

				return field[0], nil
			}
			// each frame contains: address, buildid, offset_or_ip, symbols
			framefield, err := addField(in, "frame", api.ArrayOf(api.Kind_Invalid))
			if err != nil {
				return err
			}
			addressesField, err := addField(framefield, "addresses", api.Kind_Uint64)
			if err != nil {
				return err
			}
			buildIDField, err := addField(framefield, "buildids", api.Kind_Bytes)
			if err != nil {
				return err
			}
			offsetOrIP, err := addField(framefield, "offsets_or_ips", api.Kind_Uint64)
			if err != nil {
				return err
			}

			symbolsField, err := addField(framefield, "symbols", api.Kind_String)
			if err != nil {
				return err
			}

			converter := func(ds datasource.DataSource, data datasource.Data) error {
				major, _ := majorField[0].Uint32(data)
				minor, _ := minorField[0].Uint32(data)
				inode, _ := inodeField[0].Uint64(data)

				baseAddrHash, _ := baseAddrHashField[0].Uint32(data)
				// If user stacks are disabled
				if inode == 0 {
					return nil
				}

				stackId, _ := stackField[0].Uint32(data)
				tgidLevel0, _ := tgidLevel0Field[0].Uint32(data)
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
				mtimeSec, _ := mtimeSecField[0].Int64(data)
				mtimeNsec, _ := mtimeNsecField[0].Uint32(data)

				var stackQueries []symbolizer.StackItemQuery
				var alreadyKnownSymbols []string // symbols already resolved server-side

				// The ustack operator can run both on the client and on the server side.
				// The BPF map is not available client-side (e.g. kubectl-gadget)
				if !gadgetCtx.IsClient() {
					if o.userStackMap == nil {
						logger.Warn("user stack map is not initialized")
						return nil
					}
					userStackMap := o.userStackMap()
					if userStackMap == nil {
						logger.Warn("user stack map is missing")
						return nil
					}
					var buildIDMap *ebpf.Map
					if o.buildIDMap != nil {
						buildIDMap = o.buildIDMap()
					}

					//var addressesStr, buildIDStr string
					var err error
					stackQueries, err = readUserStackMap(gadgetCtx, userStackMap, buildIDMap, stackId)
					if err != nil {
						logger.Warn(err)
						return nil
					}

					addresses := make([]uint64, 0, len(stackQueries))
					buildIDs := make([][]byte, 0, len(stackQueries))
					offsetOrIps := make([]uint64, 0, len(stackQueries))
					for _, sq := range stackQueries {
						buildIDs = append(buildIDs, sq.BuildID[:])
						addresses = append(addresses, sq.Addr)
						if sq.ValidBuildID {
							offsetOrIps = append(offsetOrIps, sq.Offset)
						} else {
							offsetOrIps = append(offsetOrIps, sq.IP)
						}
					}
					addressesField.PutUint64Array(data, addresses)
					buildIDField.PutBytesArray(data, buildIDs)
					offsetOrIP.PutUint64Array(data, offsetOrIps)

					alreadyKnownSymbols = make([]string, len(stackQueries))
				} else if o.symbolizer != nil {
					// The symbolizer might be used client-side where we don't
					// have access to BPF maps. Access data from the data source
					// instead.
					addresses, _ := addressesField.Uint64Array(data)
					buildIDs, _ := buildIDField.BytesArray(data)
					offsetsOrIPs, _ := offsetOrIP.Uint64Array(data)

					alreadyKnownSymbols, _ := symbolsField.StringArray(data)
					for i := range alreadyKnownSymbols {
						index := strings.IndexByte(alreadyKnownSymbols[i], ']')
						if index >= 0 {
							alreadyKnownSymbols[i] = alreadyKnownSymbols[i][index+1:]
						}
					}

					for i, addr := range addresses {
						if addresses[i] == 0 {
							break
						}

						if len(alreadyKnownSymbols) <= i {
							alreadyKnownSymbols = append(alreadyKnownSymbols, "")
						}

						var buildid [20]byte
						var validBuildID bool
						var offset uint64
						var ip uint64

						buildID := buildIDs[i]
						if len(buildID) == 20 {
							copy(buildid[:], buildID)
							validBuildID = true
							offset = offsetsOrIPs[i]
						} else {
							ip = offsetsOrIPs[i]
						}

						stackQueries = append(stackQueries, symbolizer.StackItemQuery{
							Addr:         addr,
							ValidBuildID: validBuildID,
							BuildID:      buildid,
							Offset:       offset,
							IP:           ip,
						})
					}
				}

				if o.symbolizer != nil {
					task := symbolizer.Task{
						Name:         fmt.Sprintf("%s/%s", containerName, comm),
						Tgid:         tgidLevel0,
						PidNumbers:   pidNumbers,
						ContainerPid: containerPid,
						Exe: symbolizer.SymbolTableKey{
							Major:     major,
							Minor:     minor,
							Ino:       inode,
							MtimeSec:  mtimeSec,
							MtimeNsec: mtimeNsec,
						},
						BaseAddrHash: baseAddrHash,
					}
					stackQueriesResponse, err := o.symbolizer.Resolve(task, stackQueries)
					if err != nil {
						logger.Warnf("symbolizer: %s", err)
						return nil
					}

					symbols := make([]string, len(stackQueriesResponse))
					for i, res := range stackQueriesResponse {
						s := res.Symbol
						if !res.Found && i < len(alreadyKnownSymbols) {
							s = alreadyKnownSymbols[i]
						}
						symbols[i] = s
					}
					symbolsField.PutStringArray(data, symbols)
				}
				return nil
			}
			o.subscriptions[ds] = append(o.subscriptions[ds], converter)
		}
	}

	if len(o.subscriptions) > 0 && o.symbolizerEnabled {
		var err error
		o.symbolizer, err = symbolizer.NewSymbolizer(o.symbolizerOpts)
		if err != nil {
			return err
		}
	}

	if len(o.subscriptions) > 0 && !gadgetCtx.IsClient() {
		// At Instantiate-time, the ebpf operator has set the MapSpec
		// variables but not yet the Map variables. We use the MapSpec to check
		// if the gadget has a user stack map. But we will only access the Map
		// at Start(), when the ebpf operator has set them.

		userStackMapAny, ok := gadgetCtx.GetVar(operators.MapSpecPrefix + ebpftypes.UserStackMapName)
		if !ok || userStackMapAny == nil {
			return errors.New("user stack map is not initialized but used. " +
				"if you are using `gadget_user_stack` as event field, " +
				"try to include <gadget/user_stack_map.h>")
		}
		_, ok = userStackMapAny.(*ebpf.MapSpec)
		if !ok {
			return errors.New("user stack map is not of expected type")
		}
		o.userStackMap = sync.OnceValue(func() *ebpf.Map {
			userStackMapAny, ok := gadgetCtx.GetVar(operators.MapPrefix + ebpftypes.UserStackMapName)
			if !ok || userStackMapAny == nil {
				return nil
			}
			userStackMap, ok := userStackMapAny.(*ebpf.Map)
			if !ok {
				return nil
			}
			return userStackMap
		})

		o.buildIDMap = sync.OnceValue(func() *ebpf.Map {
			// buildIDMap is optional. Older gadgets won't have it.
			var buildIDMap *ebpf.Map
			buildIDMapAny, ok := gadgetCtx.GetVar(operators.MapPrefix + ebpftypes.BuildIdMapName)
			if ok {
				buildIDMap, ok = buildIDMapAny.(*ebpf.Map)
				if !ok {
					return nil
				}
			}
			err := checkBuildIDMap(buildIDMap)
			if err != nil {
				logger.Warnf("%s", err)
				return nil
			}
			return buildIDMap
		})
	}

	return nil
}

func (o *OperatorInstance) Name() string {
	return Name
}

// PreStart subscribes to the datasources.
func (o *OperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	for ds, funcs := range o.subscriptions {
		for _, f := range funcs {
			ds.Subscribe(f, Priority)
		}
	}
	return nil
}

// Start can emit data. Nothing to do here.
func (o *OperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

// Stop stops emitting data. Nothing to do here.
func (o *OperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *OperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	if o.symbolizer != nil {
		o.symbolizer.Close()
	}
	return nil
}

func init() {
	operators.RegisterDataOperator(&Operator{})
}
