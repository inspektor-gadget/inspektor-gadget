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

// Package combiner is a data operator that combines data from a same data
// source coming from different targets into a single data source. This is
// useful when we run the same gadget in a distributed environment like
// Kubernetes and we want to combine the data from all the nodes on the client
// side so that we can perform further operations on the combined data, e.g.
// sorting. Notice that this operator is useful only when we have data sources
// of type array.
package combiner

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

const (
	// We need it to be the first operator to run in client side. Only operators
	// registering data sources should run before the combiner operator.
	Priority         = -500
	DataSourcePrefix = "combined"
	OperatorName     = "Combiner"
)

type combinerOperator struct{}

func (o *combinerOperator) Name() string {
	return OperatorName
}

func (o *combinerOperator) Init(params *params.Params) error {
	return nil
}

func (o *combinerOperator) GlobalParams() api.Params {
	return nil
}

func (o *combinerOperator) InstanceParams() api.Params {
	return nil
}

func getFetchAnnotation(ds datasource.DataSource) (time.Duration, error) {
	intervalAnn, ok := ds.Annotations()[api.FetchIntervalAnnotation]
	if !ok {
		return 0, errors.New("missing fetch interval annotation")
	}
	fetchInterval, err := time.ParseDuration(intervalAnn)
	if err != nil {
		return 0, fmt.Errorf("parsing fetch interval annotation to duration: %w", err)
	}
	return fetchInterval, nil
}

func (o *combinerOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (operators.DataOperatorInstance, error) {
	targetsVar, ok := gadgetCtx.GetVar(runtime.NumRunTargets)
	if !ok {
		gadgetCtx.Logger().Debugf("combiner: No targets found. Skipping combiner operator")
		return nil, nil
	}

	targets, ok := targetsVar.(int)
	if !ok {
		return nil, fmt.Errorf("invalid type for number of targets: %T, expected \"int\"", targetsVar)
	}

	if targets == 0 {
		return nil, nil
	}

	configs := make(map[datasource.DataSource]*combinerConfig)
	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() == datasource.TypeArray {
			interval, err := getFetchAnnotation(ds)
			if err != nil {
				return nil, fmt.Errorf("getting fetch annotation for ds %s: %w", ds.Name(), err)
			}

			configs[ds] = &combinerConfig{
				// TODO: What happen if we receive more than one packet for the same
				// target? We should probably have a way to handle this case.
				packetBuf: make(chan datasource.PacketArray, targets),
				interval:  interval,
			}
		}
	}

	if len(configs) != 0 {
		gadgetCtx.Logger().Debugf("combiner: array data sources found (%d). Activating combiner operator", len(configs))
		return &combinerOperatorInstance{
			targets: targets,
			configs: configs,
		}, nil
	}

	return nil, nil
}

func (o *combinerOperator) Priority() int {
	return Priority
}

type combinerConfig struct {
	// Interval to wait for data before emitting the combined data
	interval time.Duration

	// Buffer to send data to the combiner data source
	packetBuf chan datasource.PacketArray
}

type combinerOperatorInstance struct {
	// Number of targets to (ideally) wait for before emitting the combined data
	targets int

	configs map[datasource.DataSource]*combinerConfig

	done chan struct{}
}

func (o *combinerOperatorInstance) Name() string {
	return OperatorName
}

func (o *combinerOperatorInstance) InstanceParams() params.ParamDescs {
	return nil
}

func (o *combinerOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return nil
}

func (o *combinerOperatorInstance) forwardData(
	gadgetCtx operators.GadgetContext,
	config *combinerConfig,
	combinedDs datasource.DataSource,
) {
	combinedPacket, err := combinedDs.NewPacketArray()
	if err != nil {
		gadgetCtx.Logger().Debugf("combiner: failed to create new packet array: %s", err)
		return
	}
	defer func() {
		if combinedPacket != nil {
			combinedDs.Release(combinedPacket)
		}
	}()

	targetCount := 0

	var c <-chan time.Time

	if config.interval == 0 {
		// Define a maximum waiting time for data from all targets
		// TODO: Make it configurable?
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		c = timeout.C
	} else {
		// Even if we receive data from all targets, we emit the combined data
		// only after the requested interval
		ticker := time.NewTicker(config.interval)
		defer ticker.Stop()
		c = ticker.C
	}

	emitAndAllocate := func() error {
		if err := combinedDs.EmitAndRelease(combinedPacket); err != nil {
			gadgetCtx.Logger().Errorf("Failed emitting data array for ds combiner %q: %s",
				combinedDs.Name(), err)
		}

		// Allocate a new packet array for next iteration
		combinedPacket, err = combinedDs.NewPacketArray()
		if err != nil {
			// We can't continue without a new packet array
			return fmt.Errorf("creating new packet array: %w", err)
		}

		targetCount = 0
		return nil
	}

	for {
		select {
		case <-o.done:
			gadgetCtx.Logger().Debugf("combiner: done with %q", combinedDs.Name())
			return
		case inPacket := <-config.packetBuf:
			targetCount++

			// TODO: Support Append multiple packets at once?
			for i := 0; i < inPacket.Len(); i++ {
				combinedPacket.Append(inPacket.Get(i))
			}

			// For data sources that don't have an interval, we wait for data
			// from all targets before emitting the combined data.
			if config.interval == 0 && targetCount == o.targets {
				if err := emitAndAllocate(); err != nil {
					gadgetCtx.Logger().Errorf("Failed emitting and allocating combined data: %s", err)
				}
				return
			}
		case <-c:
			if config.interval == 0 {
				gadgetCtx.Logger().Warnf("Data is incomplete: timeout waiting for data from all targets (%d/%d)",
					targetCount, o.targets)

				if err := emitAndAllocate(); err != nil {
					gadgetCtx.Logger().Errorf("Failed emitting and allocating combined data: %s", err)
					return
				}

				return
			}

			if err := emitAndAllocate(); err != nil {
				gadgetCtx.Logger().Errorf("Failed emitting and allocating combined data: %s", err)
				return
			}
		}
	}
}

func (o *combinerOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	o.done = make(chan struct{})

	for ds, config := range o.configs {
		// Disable original data source to avoid other operators subscribing to it
		ds.Unreference()

		// Register a new data source that will emit the combined data
		combinedDs, err := gadgetCtx.RegisterDataSource(
			datasource.TypeArray,
			fmt.Sprintf("%s-%s", DataSourcePrefix, ds.Name()),
		)
		if err != nil {
			return fmt.Errorf("registering combiner data source for %s: %w", ds.Name(), err)
		}

		gadgetCtx.Logger().Debugf("combiner: registered ds %q", combinedDs.Name())

		// Use the same fields and annotations as the original data source
		ds.CopyFieldsTo(combinedDs)
		for k, v := range ds.Annotations() {
			combinedDs.AddAnnotation(k, v)
		}

		go o.forwardData(gadgetCtx, config, combinedDs)

		gadgetCtx.Logger().Debugf("combiner: subscribing to %q", ds.Name())

		ds.SubscribePacket(func(source datasource.DataSource, packet datasource.Packet) error {
			// Avoid keeping a reference to the original packet as it will be
			// released once the callback returns. Use Marshal/Unmarshal to
			// create a deep copy.
			b, _ := proto.Marshal(packet.Raw())
			pArray, err := combinedDs.NewPacketArrayFromRaw(b)
			if err != nil {
				return fmt.Errorf("creating packet array from raw: %w", err)
			}

			// Send the packet to the combiner data source
			config.packetBuf <- pArray

			return nil
		}, Priority)
	}

	return nil
}

func (o *combinerOperatorInstance) Start(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (o *combinerOperatorInstance) Stop(gadgetCtx operators.GadgetContext) error {
	if o.done != nil {
		close(o.done)
		o.done = nil
	}
	// TODO: Don't close the buffers here. We need to find a way to synchronize
	// the closing of the buffers with the data source still emitting data.
	// if o.pktBuffers != nil {
	//  for _, buf := range o.pktBuffers {
	//      if buf != nil {
	//          close(buf)
	//      }
	//  }
	//  o.pktBuffers = nil
	// }
	return nil
}

func (o *combinerOperatorInstance) Close(gadgetCtx operators.GadgetContext) error {
	return nil
}

var CombinerOperator = &combinerOperator{}
