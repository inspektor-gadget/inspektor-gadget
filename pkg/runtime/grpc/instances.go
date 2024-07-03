// Copyright 2023 The Inspektor Gadget authors
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

package grpcruntime

import (
	"context"
	"errors"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func (r *Runtime) RemoveGadgetInstance(ctx context.Context, runtimeParams *params.Params, id string) error {
	conn, err := r.getConnToRandomTarget(ctx, runtimeParams)
	if err != nil {
		return err
	}
	client := api.NewGadgetInstanceManagerClient(conn)
	res, err := client.RemoveGadgetInstance(ctx, &api.GadgetInstanceId{Id: id})
	if err != nil {
		return err
	}
	if res.Result != 0 {
		return errors.New(res.Message)
	}
	return nil
}

func (r *Runtime) StopGadgetInstance(ctx context.Context, runtimeParams *params.Params, id string) error {
	conn, err := r.getConnToRandomTarget(ctx, runtimeParams)
	if err != nil {
		return err
	}
	client := api.NewGadgetInstanceManagerClient(conn)
	res, err := client.StopGadgetInstance(ctx, &api.GadgetInstanceId{Id: id})
	if err != nil {
		return err
	}
	if res.Result != 0 {
		return errors.New(res.Message)
	}
	return nil
}

func (r *Runtime) GetGadgetInstances(ctx context.Context, runtimeParams *params.Params) ([]*api.GadgetInstance, error) {
	conn, err := r.getConnToRandomTarget(ctx, runtimeParams)
	if err != nil {
		return nil, err
	}
	client := api.NewGadgetInstanceManagerClient(conn)
	res, err := client.ListGadgetInstances(ctx, &api.ListGadgetInstancesRequest{})
	if err != nil {
		return nil, err
	}
	return res.GadgetInstances, nil
}

func (r *Runtime) installGadgetInstance(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValues map[string]string) error {
	gadgetCtx.Logger().Debugf("installing persistent gadget")

	conn, err := r.getConnToRandomTarget(gadgetCtx.Context(), runtimeParams)
	if err != nil {
		return err
	}
	client := api.NewGadgetInstanceManagerClient(conn)

	res, err := client.InstallGadgetInstance(gadgetCtx.Context(), &api.InstallGadgetInstanceRequest{
		GadgetInstance: &api.GadgetInstance{
			Name: runtimeParams.Get(ParamName).AsString(),
			Tags: strings.Split(runtimeParams.Get(ParamTags).AsString(), ","),
			GadgetInfo: &api.GadgetRunRequest{
				ImageName:   gadgetCtx.ImageName(),
				ParamValues: paramValues,
				Version:     api.VersionGadgetRunProtocol,
			},
		},
		EventBufferLength: 0,
	})
	if err != nil {
		return err
	}

	gadgetCtx.Logger().Debugf("installed as %q", res.GadgetInstance.Id)
	return nil
}
