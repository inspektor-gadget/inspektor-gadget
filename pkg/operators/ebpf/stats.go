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
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/bpfstats"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamGadgetStatisticsInterval = "statistics-interval"
	ParamGadgetStatisticsCount    = "statistics-count"
	EmitStatsAnn                  = "emitstats"
	StatsDSName                   = "bpfstats"
	EnableBPFStatsParam           = "enable-bpfstats"
)

func (i *ebpfOperator) GlobalParams() api.Params {
	return api.Params{
		{
			Key:          EnableBPFStatsParam,
			Description:  "Enable capturing eBPF stats",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
			Title:        "Enable eBPF stats",
		},
	}
}

func (i *ebpfOperator) Init(params *params.Params) error {
	enableBPFStats := params.Get(EnableBPFStatsParam).AsBool()
	if !enableBPFStats {
		return nil
	}

	i.gadgetObjs = make(map[operators.GadgetContext]gadgetObjs)

	// Enable stats collection
	// TODO: when to disable it?
	if err := bpfstats.EnableBPFStats(); err != nil {
		return err
	}

	return nil
}

func (i *ebpfOperator) InstantiateDataOperator(
	gadgetCtx operators.GadgetContext, paramValues api.ParamValues,
) (operators.DataOperatorInstance, error) {
	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}

	emitStatsAnn := v.GetBool(fmt.Sprintf("datasources.%s.annotations.operator.%s.%s", StatsDSName, i.Name(), EmitStatsAnn))
	if !emitStatsAnn {
		return nil, nil
	}

	if i.gadgetObjs == nil {
		return nil, fmt.Errorf("bpfstats aren't enabled")
	}

	var err error

	instance := &ebpfOperatorDataInstance{
		bpfOperator: i,
		done:        make(chan struct{}),
	}

	instance.ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, "bpfstats")
	if err != nil {
		return nil, err
	}

	intervalAnn := paramValues[ParamGadgetStatisticsInterval]
	if intervalAnn == "" {
		intervalAnn = "1000ms"
	}
	instance.interval, err = time.ParseDuration(intervalAnn)
	if err != nil {
		return nil, fmt.Errorf("parsing duration: %w", err)
	}

	countAnn := paramValues[ParamGadgetStatisticsCount]
	if countAnn == "" {
		countAnn = "0"
	}
	instance.count, err = strconv.Atoi(countAnn)
	if err != nil {
		return nil, fmt.Errorf("parsing count: %w", err)
	}

	instance.ds.AddAnnotation(api.FetchIntervalAnnotation, intervalAnn)
	instance.ds.AddAnnotation(api.FetchCountAnnotation, countAnn)
	instance.ds.AddAnnotation("cli.clear-screen-before", "true")

	if nodeName, ok := os.LookupEnv("NODE_NAME"); ok {
		instance.nodeNameField, err = instance.ds.AddField("nodeName", api.Kind_String,
			datasource.WithAnnotations(map[string]string{
				metadatav1.ColumnsWidthAnnotation: "16",
			}),
		)
		if err != nil {
			return nil, err
		}
		instance.nodeName = nodeName
	}

	// gadget-specific fields
	instance.gadgetIDField, err = instance.ds.AddField("gadgetID", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "8",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.gadgetNameField, err = instance.ds.AddField("gadgetName", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "16",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.gadgetImageField, err = instance.ds.AddField("gadgetImage", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "16",
		}),
	)
	if err != nil {
		return nil, err
	}

	// low-level fields
	instance.progIDField, err = instance.ds.AddField("progID", api.Kind_Uint32,
		datasource.WithTags("type:ebpfprogid"),
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "5",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.progNameField, err = instance.ds.AddField("progName", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			// The maximum length provided by the kernel is 16 bytes
			metadatav1.ColumnsFixedAnnotation: "16",
		}),
	)
	if err != nil {
		return nil, err
	}

	// stats fields
	instance.runtimeField, err = instance.ds.AddField("runtime", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "12",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.runcountField, err = instance.ds.AddField("runcount", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "12",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.mapMemoryField, err = instance.ds.AddField("mapMemory", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "12",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.mapCountField, err = instance.ds.AddField("mapCount", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "5",
		}),
	)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (i *ebpfOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          ParamGadgetStatisticsInterval,
			Description:  "interval in which to provide gadget statistics",
			DefaultValue: "1000ms",
			TypeHint:     api.TypeString,
			Title:        "Gadget statistics interval",
		},
		{
			Key:          ParamGadgetStatisticsCount,
			Description:  "number of cycles to provide statistics - use 0 for unlimited",
			DefaultValue: "0",
			TypeHint:     api.TypeInt,
			Title:        "Gadget statistics count",
		},
	}
}

func (i *ebpfOperator) Priority() int {
	return 0
}

type ebpfOperatorDataInstance struct {
	bpfOperator *ebpfOperator
	ds          datasource.DataSource
	interval    time.Duration
	count       int
	done        chan struct{}

	nodeNameField datasource.FieldAccessor
	nodeName      string

	// gadget-specific fields
	gadgetImageField datasource.FieldAccessor
	gadgetIDField    datasource.FieldAccessor
	gadgetNameField  datasource.FieldAccessor

	// low-level fields
	progIDField   datasource.FieldAccessor
	progNameField datasource.FieldAccessor

	// stats fields
	runtimeField   datasource.FieldAccessor
	runcountField  datasource.FieldAccessor
	mapMemoryField datasource.FieldAccessor
	mapCountField  datasource.FieldAccessor
}

func (i *ebpfOperatorDataInstance) Name() string {
	return "ebpfdataoperator"
}

type GadgetStat struct {
	GadgetID    string
	GadgetName  string
	GadgetImage string

	ProgramID   uint32
	ProgramName string

	Runtime   uint64
	Runcount  uint64
	MapMemory uint64
	MapCount  uint64
}

func (i *ebpfOperatorDataInstance) sendStats(stats []GadgetStat) error {
	arr, err := i.ds.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	for _, stat := range stats {
		d := arr.New()

		if i.nodeNameField != nil {
			i.nodeNameField.PutString(d, i.nodeName)
		}
		i.gadgetIDField.PutString(d, stat.GadgetID)
		i.gadgetNameField.PutString(d, stat.GadgetName)
		i.gadgetImageField.PutString(d, stat.GadgetImage)
		i.progIDField.PutUint32(d, stat.ProgramID)
		i.progNameField.PutString(d, stat.ProgramName)
		i.runtimeField.PutUint64(d, stat.Runtime)
		i.runcountField.PutUint64(d, stat.Runcount)
		i.mapMemoryField.PutUint64(d, stat.MapMemory)
		i.mapCountField.PutUint64(d, stat.MapCount)

		arr.Append(d)
	}

	return i.ds.EmitAndRelease(arr)
}

func (i *ebpfOperatorDataInstance) getGadgetStats() ([]GadgetStat, error) {
	stats := make([]GadgetStat, 0)

	mapSizes, err := bpfstats.GetMapsMemUsage()
	if err != nil {
		return nil, fmt.Errorf("getting map memory usage: %w", err)
	}

	// cache for prog stats
	progStats := make(map[ebpf.ProgramID]GadgetStat)

	// TODO: reduce lock contention
	i.bpfOperator.mu.Lock()
	defer i.bpfOperator.mu.Unlock()

	programToGadget := make(map[ebpf.ProgramID]operators.GadgetContext)
	for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
		for _, id := range gadgetObjs.programIDs {
			programToGadget[id] = ctx
		}
	}

	// emit all ebpf programs regardless they being part of a gadget
	var curID ebpf.ProgramID
	var nextID ebpf.ProgramID
	for {
		nextID, err = ebpf.ProgramGetNextID(curID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return nil, fmt.Errorf("getting next program ID: %w", err)
		}
		if nextID <= curID {
			break
		}
		curID = nextID
		prog, err := ebpf.NewProgramFromID(curID)
		if err != nil {
			continue
		}
		pi, err := prog.Info()
		if err != nil {
			prog.Close()
			continue
		}

		stat := GadgetStat{}

		id, _ := pi.ID()
		stat.ProgramID = uint32(id)
		stat.ProgramName = pi.Name
		runtime, _ := pi.Runtime()
		stat.Runtime = uint64(runtime)
		stat.Runcount, _ = pi.RunCount()

		mapIDs, _ := pi.MapIDs()
		for _, mapID := range mapIDs {
			stat.MapMemory += mapSizes[mapID]
			stat.MapCount += 1
		}

		// enrich with gadget information if they're part of a gadget
		if ctx, ok := programToGadget[ebpf.ProgramID(id)]; ok {
			stat.GadgetID = ctx.ID()
			stat.GadgetName = "TODO" // ctx.Name()
			stat.GadgetImage = ctx.ImageName()
		}

		stats = append(stats, stat)

		// cache the program stats. This will be used in the next loop to
		// consolidate runtime and runcount for a gadget
		progStats[ebpf.ProgramID(stat.ProgramID)] = stat

		prog.Close()
	}

	// emit consolidated information for gadgets
	for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
		stat := GadgetStat{
			GadgetID:    ctx.ID(),
			GadgetName:  "TODO", /*ctx.Name()*/
			GadgetImage: ctx.ImageName(),
		}

		for _, id := range gadgetObjs.programIDs {
			stat.Runtime += progStats[id].Runtime
			stat.Runcount += progStats[id].Runcount
		}

		for _, mapID := range gadgetObjs.mapIDs {
			stat.MapMemory += mapSizes[mapID]
			stat.MapCount += 1
		}

		stats = append(stats, stat)
	}

	return stats, nil
}

func (i *ebpfOperatorDataInstance) Start(gadgetCtx operators.GadgetContext) error {
	go func() {
		ctr := 0
		ticker := time.NewTicker(i.interval)
		for {
			select {
			case <-i.done:
				return
			case <-ticker.C:
				stats, err := i.getGadgetStats()
				if err != nil {
					gadgetCtx.Logger().Errorf("Failed to get stats: %v", err)
					continue
				}
				if err := i.sendStats(stats); err != nil {
					gadgetCtx.Logger().Errorf("Failed to emit stats: %v", err)
					continue
				}
				ctr++
				// TODO: client remians connected even if the gadget is stopped
				if i.count > 0 && ctr >= i.count {
					fmt.Printf("Done\n")
					return
				}
			}
		}
	}()

	return nil
}

func (i *ebpfOperatorDataInstance) Stop(gadgetCtx operators.GadgetContext) error {
	close(i.done)
	return nil
}
