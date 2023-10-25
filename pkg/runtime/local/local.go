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
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	runTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type Runtime struct {
	catalog *runtime.Catalog
}

type ForwardOperatorInstances interface {
	SetOperatorInstances(instances operators.OperatorInstances)
}

func New() *Runtime {
	return &Runtime{
		catalog: prepareCatalog(),
	}
}

func prepareCatalog() *runtime.Catalog {
	gadgetInfos := make([]*runtime.GadgetInfo, 0)
	for _, gadgetDesc := range gadgetregistry.GetAll() {
		gadgetInfos = append(gadgetInfos, runtime.GadgetInfoFromGadgetDesc(gadgetDesc))
	}
	operatorInfos := make([]*runtime.OperatorInfo, 0)
	for _, operator := range operators.GetAll() {
		operatorInfos = append(operatorInfos, runtime.OperatorToOperatorInfo(operator))
	}
	return &runtime.Catalog{
		Gadgets:   gadgetInfos,
		Operators: operatorInfos,
	}
}

func (r *Runtime) Init(globalRuntimeParams *params.Params) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s must be run as root to be able to run eBPF programs", filepath.Base(os.Args[0]))
	}

	err := host.Init(host.Config{})
	if err != nil {
		return err
	}

	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	return nil
}

func (r *Runtime) GetGadgetInfo(_ context.Context, desc gadgets.GadgetDesc, pars *params.Params, args []string) (*runTypes.GadgetInfo, error) {
	runDesc, ok := desc.(runTypes.RunGadgetDesc)
	if !ok {
		return nil, fmt.Errorf("GetGadgetInfo not supported for gadget %s", desc.Name())
	}
	return runDesc.GetGadgetInfo(pars, args)
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (runtime.CombinedGadgetResult, error) {
	log := gadgetCtx.Logger()

	log.Debugf("running with local runtime")

	gadget, ok := gadgetCtx.GadgetDesc().(gadgets.GadgetInstantiate)
	if !ok {
		return nil, errors.New("gadget not instantiable")
	}

	operatorsParamCollection := gadgetCtx.OperatorsParamCollection()

	// Create gadget instance
	gadgetInstance, err := gadget.NewInstance()
	if err != nil {
		return nil, fmt.Errorf("instantiating gadget: %w", err)
	}

	// Initialize gadgets, if needed
	if initClose, ok := gadgetInstance.(gadgets.InitCloseGadget); ok {
		log.Debugf("calling gadget.Init()")
		err = initClose.Init(gadgetCtx)
		if err != nil {
			return nil, fmt.Errorf("initializing gadget: %w", err)
		}
		defer func() {
			log.Debugf("calling gadget.Close()")
			initClose.Close()
		}()
	}

	// Install operators
	operatorInstances, err := gadgetCtx.Operators().Instantiate(gadgetCtx, gadgetInstance, operatorsParamCollection)
	if err != nil {
		return nil, fmt.Errorf("instantiating operators: %w", err)
	}
	log.Debugf("found %d operators: ", len(gadgetCtx.Operators()))
	for _, operator := range gadgetCtx.Operators() {
		log.Debugf("  %s", operator.Name())
	}

	// Set event handler
	if setter, ok := gadgetInstance.(gadgets.EventHandlerSetter); ok {
		log.Debugf("set event handler")
		setter.SetEventHandler(gadgetCtx.Parser().EventHandlerFunc(operatorInstances.Enrich))
	}

	// Set event handler for array results
	if setter, ok := gadgetInstance.(gadgets.EventHandlerArraySetter); ok {
		log.Debugf("set event handler for arrays")
		setter.SetEventHandlerArray(gadgetCtx.Parser().EventHandlerFuncArray(operatorInstances.Enrich))
	}

	// Set event enricher (currently only used by profile/cpu)
	if setter, ok := gadgetInstance.(gadgets.EventEnricherSetter); ok {
		log.Debugf("set event enricher")
		setter.SetEventEnricher(operatorInstances.Enrich)
	}

	log.Debug("calling operator.PreGadgetRun()")
	err = operatorInstances.PreGadgetRun()
	if err != nil {
		return nil, fmt.Errorf("gadget prerun: %w", err)
	}
	defer func() {
		log.Debug("calling operator.PostGadgetRun()")
		operatorInstances.PostGadgetRun()
	}()

	// Temporary workaround to expose operators to gadgets
	if forwarder, ok := gadgetInstance.(ForwardOperatorInstances); ok {
		forwarder.SetOperatorInstances(operatorInstances)
	}

	if run, ok := gadgetInstance.(gadgets.RunGadget); ok {
		log.Debugf("calling gadget.Run()")
		err := run.Run(gadgetCtx)
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				gadgetCtx.Logger().Debugf("running gadget: verifier error: %+v\n", ve)
			}
			return nil, fmt.Errorf("running gadget: %w", err)
		}
		return nil, nil
	}
	if runWithResult, ok := gadgetInstance.(gadgets.RunWithResultGadget); ok {
		log.Debugf("calling gadget.RunWithResult()")
		out, err := runWithResult.RunWithResult(gadgetCtx)
		if err != nil {
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				gadgetCtx.Logger().Debugf("running (with result) gadget: verifier error: %+v\n", ve)
			}
			return nil, fmt.Errorf("running (with result) gadget: %w", err)
		}
		return runtime.CombinedGadgetResult{"": &runtime.GadgetResult{Payload: out}}, nil
	}
	return nil, errors.New("gadget not runnable")
}

func (r *Runtime) GetCatalog() (*runtime.Catalog, error) {
	return r.catalog, nil
}

func (r *Runtime) SetDefaultValue(key params.ValueHint, value string) {
	panic("not supported, yet")
}

func (r *Runtime) GetDefaultValue(key params.ValueHint) (string, bool) {
	return "", false
}
