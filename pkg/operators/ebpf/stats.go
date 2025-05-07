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

package ebpfoperator

import (
	"errors"
	"fmt"
	"os"
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
	EmitStatsAnn                  = "emitstats"
	ParamAllProgramsStats         = "all"
	StatsDSName                   = "bpfstats"
)

func (o *ebpfOperator) GlobalParams() api.Params {
	return nil
}

func (o *ebpfOperator) Init(params *params.Params) error {
	return nil
}

func (o *ebpfOperator) InstantiateDataOperator(
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

	emitStatsAnn := v.GetBool(fmt.Sprintf("operator.%s.%s", o.Name(), EmitStatsAnn))
	if !emitStatsAnn {
		return nil, nil
	}

	var err error

	instance := &ebpfOperatorDataInstance{
		bpfOperator:      o,
		done:             make(chan struct{}),
		allProgramsStats: paramValues[ParamAllProgramsStats] == "true",
	}

	instance.ds, err = gadgetCtx.RegisterDataSource(datasource.TypeArray, StatsDSName)
	if err != nil {
		return nil, err
	}

	intervalAnn := paramValues[ParamGadgetStatisticsInterval]
	instance.interval, err = time.ParseDuration(intervalAnn)
	if err != nil {
		return nil, fmt.Errorf("parsing duration: %w", err)
	}

	instance.ds.AddAnnotation(api.FetchIntervalAnnotation, intervalAnn)
	instance.ds.AddAnnotation("cli.clear-screen-before", "true")

	if nodeName, ok := os.LookupEnv("NODE_NAME"); ok {
		instance.nodeNameField, err = instance.ds.AddField("nodeName", api.Kind_String,
			datasource.WithAnnotations(map[string]string{
				metadatav1.TemplateAnnotation: "node",
				"metrics.type":                "key",
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
			metadatav1.DescriptionAnnotation:  "Unique ID assigned to each Gadget instance",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.gadgetNameField, err = instance.ds.AddField("gadgetName", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "16",
			metadatav1.DescriptionAnnotation:  "Name of the Gadget instance",
			"metrics.type":                    "key",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.gadgetImageField, err = instance.ds.AddField("gadgetImage", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation: "16",
			metadatav1.DescriptionAnnotation:  "Name of the Gadget image (like trace_open, trace_exec, etc.)",
			"metrics.type":                    "key",
		}),
	)
	if err != nil {
		return nil, err
	}

	// low-level fields
	// TODO: how to disable it based on the programs param?
	instance.progIDField, err = instance.ds.AddField("progID", api.Kind_Uint32,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
			metadatav1.DescriptionAnnotation:      "eBPF program ID assigned by the Linux kernel",
			metadatav1.ColumnsWidthAnnotation:     "5",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.progNameField, err = instance.ds.AddField("progName", api.Kind_String,
		datasource.WithAnnotations(map[string]string{
			// The maximum length provided by the kernel is 16 bytes
			metadatav1.ColumnsFixedAnnotation: "16",
			metadatav1.DescriptionAnnotation:  "Name of the eBPF program",
			"metrics.type":                    "key",
		}),
	)
	if err != nil {
		return nil, err
	}

	// stats fields
	instance.runtimeField, err = instance.ds.AddField("runtime", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			// TODO: provide human readable format
			metadatav1.ColumnsWidthAnnotation:     "12",
			metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
			metadatav1.DescriptionAnnotation:      "Time that the eBPF program or Gadget has run in nanoseconds",
			"metrics.type":                        "counter",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.runcountField, err = instance.ds.AddField("runcount", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation:     "12",
			metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
			metadatav1.DescriptionAnnotation:      "Number of times the eBPF program or Gadget has run",
			"metrics.type":                        "counter",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.mapMemoryField, err = instance.ds.AddField("mapMemory", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			// TODO provide human readable format
			metadatav1.ColumnsWidthAnnotation:     "12",
			metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
			metadatav1.DescriptionAnnotation:      "Memory used by maps in bytes",
			"metrics.type":                        "gauge",
		}),
	)
	if err != nil {
		return nil, err
	}
	instance.mapCountField, err = instance.ds.AddField("mapCount", api.Kind_Uint64,
		datasource.WithAnnotations(map[string]string{
			metadatav1.ColumnsWidthAnnotation:     "5",
			metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
			metadatav1.DescriptionAnnotation:      "Number of maps used by the eBPF program or Gadget",
			"metrics.type":                        "gauge",
		}),
	)
	if err != nil {
		return nil, err
	}

	return instance, nil
}

func (o *ebpfOperator) InstanceParams() api.Params {
	return api.Params{
		{
			Key:          ParamGadgetStatisticsInterval,
			Description:  "interval in which to provide gadget statistics",
			DefaultValue: "1000ms",
			TypeHint:     api.TypeDuration,
			Title:        "Gadget statistics interval",
		},
		{
			Key:          ParamAllProgramsStats,
			Description:  "Collect statistics for all eBPF programs",
			DefaultValue: "false",
			TypeHint:     api.TypeBool,
			Title:        "All programs statistics",
		},
	}
}

func (o *ebpfOperator) Priority() int {
	return 0
}

type ebpfOperatorDataInstance struct {
	bpfOperator *ebpfOperator
	ds          datasource.DataSource
	interval    time.Duration
	done        chan struct{}

	// used to emit incremental values
	oldProgStats map[ebpf.ProgramID]progStat

	// if true stats are collected with programs granularity
	allProgramsStats bool

	nodeNameField datasource.FieldAccessor
	nodeName      string

	// gadget-specific fields
	gadgetIDField    datasource.FieldAccessor
	gadgetNameField  datasource.FieldAccessor
	gadgetImageField datasource.FieldAccessor

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

type stat struct {
	gadgetID    string
	gadgetName  string
	gadgetImage string

	programID   uint32
	programName string

	runtime   uint64
	runcount  uint64
	mapMemory uint64
	mapCount  uint64
}

type progStat struct {
	runtime  uint64
	runcount uint64
}

func (i *ebpfOperatorDataInstance) sendStats(stats []stat) error {
	arr, err := i.ds.NewPacketArray()
	if err != nil {
		return fmt.Errorf("creating new packet: %w", err)
	}

	for _, stat := range stats {
		d := arr.New()

		if i.nodeNameField != nil {
			i.nodeNameField.PutString(d, i.nodeName)
		}
		i.gadgetIDField.PutString(d, stat.gadgetID)
		i.gadgetNameField.PutString(d, stat.gadgetName)
		i.gadgetImageField.PutString(d, stat.gadgetImage)
		if i.allProgramsStats {
			i.progIDField.PutUint32(d, stat.programID)
			i.progNameField.PutString(d, stat.programName)
		}
		i.runtimeField.PutUint64(d, stat.runtime)
		i.runcountField.PutUint64(d, stat.runcount)
		i.mapMemoryField.PutUint64(d, stat.mapMemory)
		i.mapCountField.PutUint64(d, stat.mapCount)

		arr.Append(d)
	}

	return i.ds.EmitAndRelease(arr)
}

func getProgramStats(cache map[ebpf.ProgramID]progStat, id ebpf.ProgramID) (progStat, error) {
	if stat, ok := cache[id]; ok {
		return stat, nil
	}

	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return progStat{}, err
	}
	defer prog.Close()

	pi, err := prog.Info()
	if err != nil {
		return progStat{}, err
	}

	runtime, _ := pi.Runtime()
	runcount, _ := pi.RunCount()

	stat := progStat{
		runtime:  uint64(runtime),
		runcount: runcount,
	}
	cache[id] = stat

	return stat, nil
}

func (i *ebpfOperatorDataInstance) getStats() ([]stat, error) {
	stats := make([]stat, 0)

	mapSizes, err := bpfstats.GetMapsMemUsage()
	if err != nil {
		return nil, fmt.Errorf("getting map memory usage: %w", err)
	}

	i.bpfOperator.mu.Lock()
	defer i.bpfOperator.mu.Unlock()

	oldStats := i.oldProgStats
	i.oldProgStats = make(map[ebpf.ProgramID]progStat)

	// emit consolidated stats for gadgets
	if !i.allProgramsStats {
		cache := make(map[ebpf.ProgramID]progStat)

		for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
			stat := stat{
				gadgetID:    ctx.ID(),
				gadgetName:  ctx.Name(),
				gadgetImage: ctx.ImageName(),
			}

			for _, id := range gadgetObjs.programIDs {
				progStat, err := getProgramStats(cache, id)
				if err != nil {
					return nil, fmt.Errorf("getting program stats: %w", err)
				}

				i.oldProgStats[id] = progStat
				oldProgStats := oldStats[id]

				stat.runtime += progStat.runtime - oldProgStats.runtime
				stat.runcount += progStat.runcount - oldProgStats.runcount
			}

			for _, mapID := range gadgetObjs.mapIDs {
				stat.mapMemory += mapSizes[mapID]
				stat.mapCount += 1
			}

			stats = append(stats, stat)
		}

		return stats, nil
	}

	// emit per ebpf programs stats
	programToGadget := make(map[ebpf.ProgramID]operators.GadgetContext)
	for ctx, gadgetObjs := range i.bpfOperator.gadgetObjs {
		for _, id := range gadgetObjs.programIDs {
			programToGadget[id] = ctx
		}
	}

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

		stat := stat{}

		id, _ := pi.ID()
		stat.programID = uint32(id)
		stat.programName = pi.Name
		runtime, _ := pi.Runtime()
		stat.runtime = uint64(runtime)
		stat.runcount, _ = pi.RunCount()

		i.oldProgStats[curID] = progStat{
			runtime:  stat.runtime,
			runcount: stat.runcount,
		}

		oldProgStat := oldStats[curID]
		stat.runtime -= oldProgStat.runtime
		stat.runcount -= oldProgStat.runcount

		mapIDs, _ := pi.MapIDs()
		for _, mapID := range mapIDs {
			stat.mapMemory += mapSizes[mapID]
			stat.mapCount += 1
		}

		// enrich with gadget information if they're part of a gadget
		if ctx, ok := programToGadget[ebpf.ProgramID(id)]; ok {
			stat.gadgetID = ctx.ID()
			stat.gadgetName = ctx.Name()
			stat.gadgetImage = ctx.ImageName()
		}

		stats = append(stats, stat)

		prog.Close()
	}

	return stats, nil
}

func (i *ebpfOperatorDataInstance) Start(gadgetCtx operators.GadgetContext) error {
	if err := bpfstats.EnableBPFStats(); err != nil {
		return fmt.Errorf("enabling bpf stats: %w", err)
	}

	go func() {
		ticker := time.NewTicker(i.interval)
		for {
			select {
			case <-i.done:
				return
			case <-ticker.C:
				stats, err := i.getStats()
				if err != nil {
					gadgetCtx.Logger().Errorf("Failed to get stats: %v", err)
					continue
				}
				if err := i.sendStats(stats); err != nil {
					gadgetCtx.Logger().Errorf("Failed to emit stats: %v", err)
					continue
				}
			}
		}
	}()

	return nil
}

func (i *ebpfOperatorDataInstance) Stop(gadgetCtx operators.GadgetContext) error {
	defer close(i.done)

	if err := bpfstats.DisableBPFStats(); err != nil {
		return fmt.Errorf("disabling bpf stats: %w", err)
	}

	return nil
}
