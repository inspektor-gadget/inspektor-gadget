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
	"fmt"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (r *Runtime) runGadget(runner runtime.Runner, gadget gadgets.GadgetInstantiate, operatorPerGadgetParamCollection params.Collection) error {
	log := runner.Logger()

	// Create gadget instance
	gadgetInstance, err := gadget.NewInstance(runner)
	if err != nil {
		return fmt.Errorf("instantiate gadget: %w", err)
	}

	// Deferring getting results and closing to make sure operators got their chance to clean up properly beforehand
	defer func() {
		if closer, ok := gadgetInstance.(gadgets.CloseGadget); ok {
			log.Debugf("calling gadget.Close()")
			closer.Close()
		}
		if results, ok := gadgetInstance.(gadgets.GadgetResult); ok {
			res, err := results.Result()
			log.Debugf("setting result")
			runner.SetResult(res, err)
		}
	}()

	// Install operators
	err = runner.Operators().PreGadgetRun(runner, gadgetInstance, operatorPerGadgetParamCollection)
	if err != nil {
		return fmt.Errorf("starting operators: %w", err)
	}
	defer runner.Operators().PostGadgetRun()
	log.Debugf("found %d operators", len(runner.Operators()))

	if gadget.Type() == gadgets.TypeTraceIntervals {
		// Enable interval pushes
		log.Debugf("enabling snapshots")
		runner.Parser().EnableSnapshots(runner.Context(), time.Second, 2)
	}

	// Set event handler
	if setter, ok := gadgetInstance.(gadgets.EventHandlerSetter); ok {
		log.Debugf("set event handler")
		switch gadget.Type() {
		default:
			setter.SetEventHandler(runner.Parser().EventHandlerFunc(runner.Operators().Enrich))
			// setter.SetEventHandler(runner.Parser().EventHandlerFuncNew(runner.Operators().Enricher))
		}
	}

	// Set event handler for array results
	if setter, ok := gadgetInstance.(gadgets.EventHandlerArraySetter); ok {
		log.Debugf("set event handler for arrays")
		switch gadget.Type() {
		default:
			setter.SetEventHandlerArray(runner.Parser().EventHandlerFuncArray(runner.Operators().Enrich))
			// setter.SetEventHandlerArray(runner.Parser().EventHandlerFuncArrayNew(runner.Operators().Enricher))
		case gadgets.TypeTraceIntervals:
			setter.SetEventHandlerArray(runner.Parser().EventHandlerFuncSnapshot("main", runner.Operators().Enrich)) // TODO: "main" is the node
			// setter.SetEventHandlerArray(runner.Parser().EventHandlerFuncSnapshotNew("main", runner.Operators().Enricher)) // TODO: "main" is the node
		}
	}

	// Set event handler (currently only used by profile/cpu)
	if setter, ok := gadgetInstance.(gadgets.EventEnricherSetter); ok {
		log.Debugf("set event enricher")
		setter.SetEventEnricher(runner.Operators().Enrich)
		// setter.SetEventEnricher(runner.Operators().Enricher(func(a any) error {
		// 	return nil
		// }))
	}

	if startstop, ok := gadgetInstance.(gadgets.StartStopAltGadget); ok {
		log.Debugf("calling gadget.StartAlt()")
		err := startstop.StartAlt()
		if err != nil {
			startstop.StopAlt()
			return fmt.Errorf("run gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.StopAlt()")
			startstop.StopAlt()
		}()
	} else if startstop, ok := gadgetInstance.(gadgets.StartStopGadget); ok {
		log.Debugf("calling gadget.Start()")
		err := startstop.Start()
		if err != nil {
			startstop.Stop()
			return fmt.Errorf("run gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Stop()")
			startstop.Stop()
		}()
	}

	log.Debugf("running")

	if gadget.Type() != gadgets.TypeOneShot {
		// Wait for context to close
		<-runner.Context().Done()
	}

	log.Debugf("stopping gadget")
	return nil
}
