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

package local

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	ocioperator "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func (r *Runtime) GetOCIGadgetInfo(gadgetCtx runtime.GadgetContext) (*api.GadgetInfo, error) {
	ociOp := ocioperator.OciHandler

	ociParams := gadgetCtx.LocalOperatorsParamCollection()["oci"]

	opInst, err := ociOp.Instantiate(gadgetCtx, ociParams)
	if err != nil {
		return nil, fmt.Errorf("instantiating: %w", err)
	}

	err = opInst.Prepare()
	if err != nil {
		return nil, fmt.Errorf("prepare: %w", err)
	}

	return gadgetCtx.SerializeGadgetInfo()
}

func (r *Runtime) RunOCIGadget(gadgetCtx runtime.GadgetContext) error {
	ociOp := ocioperator.OciHandler

	ociParams := gadgetCtx.LocalOperatorsParamCollection()["oci"]

	opInst, err := ociOp.Instantiate(gadgetCtx, ociParams)
	if err != nil {
		return fmt.Errorf("instantiating: %w", err)
	}

	err = opInst.Prepare()
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}

	gadgetCtx.CallPrepareCallbacks()
	// TODO: Send GadgetInfo

	// The following will actually be handled by another operator
	for _, ds := range gadgetCtx.GetDataSources() {
		sink := gadgetCtx.GetSinkForDataSource(ds)
		if sink == nil {
			// Don't subscribe if we don't have a sink
			continue
		}

		gadgetCtx.Logger().Debugf("subscribing to %s", ds.Name())

		ds.Subscribe(func(ds datasource.DataSource, data datasource.Data) error {
			sink(ds, data)
			return nil
		}, 10000)
	}

	err = opInst.PreGadgetRun()
	if err != nil {
		return fmt.Errorf("preGadgetRun: %w", err)
	}

	<-gadgetCtx.Context().Done()

	err = opInst.PostGadgetRun()
	if err != nil {
		return fmt.Errorf("postGadgetRun: %w", err)
	}

	return nil
}
