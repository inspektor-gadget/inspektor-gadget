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
	Priority             = -500
	DataSourcePrefix     = "combined"
	OperatorName         = "Combiner"
	OperatorInstanceName = "CombinerInstance"
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

func (o *combinerOperator) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (operators.DataOperatorInstance, error) {
	activate := false

	targetsVar, ok := gadgetCtx.GetVar(runtime.RunTargets)
	if !ok {
		gadgetCtx.Logger().Debugf("No targets found. Skipping combiner operator")
		return nil, nil
	}

	targets, ok := targetsVar.(int)
	if !ok {
		return nil, fmt.Errorf("invalid type for number of targets: %T, expected \"int\"", targetsVar)
	}
	if targets > 0 {
		for _, ds := range gadgetCtx.GetDataSources() {
			if ds.Type() == datasource.TypeArray {
				gadgetCtx.Logger().Debugf("Array data source found (%s). Activating combiner operator", ds.Name())
				activate = true
				break
			}
		}
	}

	if !activate {
		return nil, nil
	}

	return &combinerOperatorInstance{
		targets:    targets,
		pktBuffers: make(map[string]chan datasource.PacketArray),
	}, nil
}

func (o *combinerOperator) Priority() int {
	return Priority
}

type combinerOperatorInstance struct {
	// Number of targets to (ideally) wait for before emitting the combined data
	targets int

	// Map of packet buffers to send data to the combiner data source
	pktBuffers map[string]chan datasource.PacketArray

	done chan struct{}
}

func (o *combinerOperatorInstance) Name() string {
	return OperatorInstanceName
}

func (o *combinerOperatorInstance) InstanceParams() params.ParamDescs {
	return nil
}

func (o *combinerOperatorInstance) ExtraParams(gadgetCtx operators.GadgetContext) api.Params {
	return nil
}

func forwardData(
	gadgetCtx operators.GadgetContext,
	combinedDs datasource.DataSource,
	packetBuf <-chan datasource.PacketArray,
	done <-chan struct{},
	targets int,
) {
	combinedPacket, err := combinedDs.NewPacketArray()
	if err != nil {
		gadgetCtx.Logger().Debugf("failed to create new packet array: %s", err)
	}
	defer func() {
		if combinedPacket != nil {
			combinedDs.Release(combinedPacket)
		}
	}()

	count := 0

	var c <-chan time.Time

	periodicity, ok := combinedDs.Annotations()[datasource.PeriodicityAnnotation]
	if !ok {
		gadgetCtx.Logger().Errorf("combiner: periodicity was not set for ds %s", combinedDs.Name())
		return
	}

	switch periodicity {
	case string(datasource.PeriodicityNone):
		// Define a maximum waiting time for data from all targets
		// TODO: Make it configurable?
		timeout := time.NewTimer(5 * time.Second)
		defer timeout.Stop()
		c = timeout.C
	case string(datasource.PeriodicityByInterval):
		// For data sources that have periodicity, even if we receive data from
		// all targets, we emit the combined data only after a certain interval
		// TODO: Make interval configurable
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		c = ticker.C
	default:
		gadgetCtx.Logger().Errorf("combiner: invalid periodicity %s for ds %s", periodicity, combinedDs.Name())
	}

	emitAndAllocate := func() error {
		gadgetCtx.Logger().Debug("combiner: emitting data array")

		if err := combinedDs.EmitAndRelease(combinedPacket); err != nil {
			gadgetCtx.Logger().Errorf("failed to emit data array for ds combiner %s: %s",
				combinedDs.Name(), err)
		}

		// Allocate a new packet array for next iteration
		combinedPacket, err = combinedDs.NewPacketArray()
		if err != nil {
			// We can't continue without a new packet array
			return fmt.Errorf("creating new packet array: %w", err)
		}

		count = 0
		return nil
	}

	for {
		select {
		case <-done:
			gadgetCtx.Logger().Debug("combiner: done")
			return
		case inPacket := <-packetBuf:
			if inPacket == nil {
				continue
			}

			count++
			gadgetCtx.Logger().Debugf("combiner: received data from %d/%d targets", count, targets)

			// TODO: Support Append multiple packets at once?
			for i := 0; i < inPacket.Len(); i++ {
				combinedPacket.Append(inPacket.Get(i))
			}

			// For data sources that do not have periodicity, we wait for data
			// from all targets before emitting the combined data
			if periodicity == string(datasource.PeriodicityNone) {
				if count == targets {
					if err := emitAndAllocate(); err != nil {
						gadgetCtx.Logger().Errorf("emitting and allocating data: %s", err)
					}
					return
				}
			}
		case <-c:
			if periodicity == string(datasource.PeriodicityNone) {
				gadgetCtx.Logger().Warnf("Data is incomplete: timeout waiting for data from all targets (%d/%d)", count, targets)
			}
			if err := emitAndAllocate(); err != nil {
				gadgetCtx.Logger().Errorf("emitting and allocating data: %s", err)
				return
			}
		}
	}
}

func (o *combinerOperatorInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	o.done = make(chan struct{})

	for _, ds := range gadgetCtx.GetDataSources() {
		if ds.Type() != datasource.TypeArray {
			continue
		}

		// Disable original data source to avoid other operators subscribing to it
		ds.SetRequested(false)

		gadgetCtx.Logger().Debugf("combiner: annotations %v", ds.Annotations())

		// Register a new data source that will emit the combined data
		combinedDs, err := gadgetCtx.RegisterDataSource(
			datasource.TypeArray,
			fmt.Sprintf("%s-%s", DataSourcePrefix, ds.Name()),
		)
		if err != nil {
			return fmt.Errorf("registering combiner data source for %s: %w", combinedDs.Name(), err)
		}

		gadgetCtx.Logger().Debugf("%s: registered ds %s", o.Name(), combinedDs.Name())

		// Use the same fields and annotations as the original data source
		ds.CopyFieldsTo(combinedDs)
		for k, v := range ds.Annotations() {
			combinedDs.AddAnnotation(k, v)
		}

		o.pktBuffers[ds.Name()] = make(chan datasource.PacketArray, o.targets)
		go forwardData(gadgetCtx, combinedDs, o.pktBuffers[ds.Name()], o.done, o.targets)

		gadgetCtx.Logger().Debugf("%s: subscribing to %s", o.Name(), ds.Name())

		ds.SubscribePacket(func(source datasource.DataSource, packet datasource.Packet) error {
			gadgetCtx.Logger().Debug("Received data array ... Sending to combiner")

			// Use Marshal/Unmarshal to create a deep copy
			b, _ := proto.Marshal(packet.Raw())
			pArray, err := combinedDs.NewPacketArrayFromRaw(b)
			if err != nil {
				return fmt.Errorf("creating packet array from raw: %w", err)
			}

			// Send the packet to the combiner data source
			o.pktBuffers[ds.Name()] <- pArray

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
	if o.pktBuffers != nil {
		for _, buf := range o.pktBuffers {
			if buf != nil {
				close(buf)
			}
		}
		o.pktBuffers = nil
	}
	return nil
}

var CombinerOperator = &combinerOperator{}
