// Copyright 2022-2023 The Inspektor Gadget authors
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

package local

import (
	"errors"
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type Runtime struct{}

func (r *Runtime) Init(runtimeParams *params.Params) error {
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) RunGadget(
	gadgetCtx runtime.GadgetContext,
) ([]byte, error) {
	logger := gadgetCtx.Logger()

	logger.Debugf("running with local runtime")

	gadgetInst, ok := gadgetCtx.GadgetDesc().(gadgets.GadgetInstantiate)
	if !ok {
		return []byte{}, errors.New("gadget not instantiable")
	}

	return r.runGadget(gadgetCtx, gadgetInst)
}

func (r *Runtime) runGadget(
	gadgetCtx runtime.GadgetContext,
	gadget gadgets.GadgetInstantiate,
) (out []byte, err error) {
	log := gadgetCtx.Logger()

	operatorsParamCollection := gadgetCtx.OperatorsParamCollection()

	// Create gadget instance
	gadgetInstance, err := gadget.NewInstance(gadgetCtx)
	if err != nil {
		return out, fmt.Errorf("instantiating gadget: %w", err)
	}

	// Deferring getting results and closing to make sure operators got their chance to clean up properly beforehand
	defer func() {
		if closer, ok := gadgetInstance.(gadgets.CloseGadget); ok {
			log.Debugf("calling gadget.Close()")
			closer.Close()
		}

		// No need to get results if gadget failed
		if err != nil {
			return
		}

		if results, ok := gadgetInstance.(gadgets.GadgetResult); ok {
			log.Debugf("getting result")
			out, err = results.Result()
			if err != nil {
				err = fmt.Errorf("getting result: %w", err)
			}
		}
	}()

	// Install operators
	operatorInstances, err := gadgetCtx.Operators().Instantiate(gadgetCtx, gadgetInstance, operatorsParamCollection)
	if err != nil {
		return out, fmt.Errorf("instantiating operators: %w", err)
	}
	defer operatorInstances.Close()
	log.Debugf("found %d operators", len(gadgetCtx.Operators()))

	if gadget.Type() == gadgets.TypeTraceIntervals {
		// Enable interval pushes
		interval := gadgetCtx.GadgetParams().Get(gadgets.ParamInterval).AsInt()
		log.Debugf("enabling snapshots every %d seconds", interval)
		gadgetCtx.Parser().EnableSnapshots(gadgetCtx.Context(), time.Second, interval)
	}

	// Set event handler
	if setter, ok := gadgetInstance.(gadgets.EventHandlerSetter); ok {
		log.Debugf("set event handler")
		switch gadget.Type() {
		default:
			setter.SetEventHandler(gadgetCtx.Parser().EventHandlerFunc(operatorInstances.Enrich))
			// setter.SetEventHandler(gadgetCtx.Parser().EventHandlerFuncNew(operatorInstances.Enricher))
		}
	}

	// Set event handler for array results
	if setter, ok := gadgetInstance.(gadgets.EventHandlerArraySetter); ok {
		log.Debugf("set event handler for arrays")
		switch gadget.Type() {
		default:
			setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncArray(operatorInstances.Enrich))
			// setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncArrayNew(operatorInstances.Enricher))
		case gadgets.TypeTraceIntervals:
			setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncSnapshot("main", operatorInstances.Enrich)) // TODO: "main" is the node
			// setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncSnapshotNew("main", operatorInstances.Enricher)) // TODO: "main" is the node
		}
	}

	// Set event handler (currently only used by profile/cpu)
	if setter, ok := gadgetInstance.(gadgets.EventEnricherSetter); ok {
		log.Debugf("set event enricher")
		setter.SetEventEnricher(operatorInstances.Enrich)
		// setter.SetEventEnricher(gadgetCtx.Operators().Enricher(func(a any) error {
		// 	return nil
		// }))
	}

	if startstop, ok := gadgetInstance.(gadgets.StartStopAltGadget); ok {
		log.Debugf("calling gadget.StartAlt()")
		err := startstop.StartAlt()
		if err != nil {
			return out, fmt.Errorf("starting gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.StopAlt()")
			startstop.StopAlt()
		}()
	} else if startstop, ok := gadgetInstance.(gadgets.StartStopGadget); ok {
		log.Debugf("calling gadget.Start()")
		err := startstop.Start()
		if err != nil {
			return out, fmt.Errorf("starting gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Stop()")
			startstop.Stop()
		}()
	}

	log.Debugf("running")

	if gadget.Type() != gadgets.TypeOneShot {
		// Wait for context to close
		<-gadgetCtx.Context().Done()
	}

	log.Debugf("stopping gadget")
	return out, nil
}
