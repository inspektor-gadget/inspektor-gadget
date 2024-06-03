// Copyright 2023-2024 The Inspektor Gadget authors
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
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/hashicorp/go-multierror"
	"github.com/moby/moby/pkg/namesgenerator"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func (r *Runtime) RemoveGadgetInstance(ctx context.Context, runtimeParams *params.Params, id string) error {
	return r.runInstanceManagerClientForTargets(ctx, runtimeParams, func(target target, client api.GadgetInstanceManagerClient) error {
		res, err := client.RemoveGadgetInstance(ctx, &api.GadgetInstanceId{Id: id})
		if err != nil {
			return err
		}
		if res.Result != 0 {
			return errors.New(res.Message)
		}
		return nil
	})
}

func (r *Runtime) GetGadgetInstances(ctx context.Context, runtimeParams *params.Params) (instances []*api.GadgetInstance, err error) {
	var mu sync.Mutex
	err = r.runInstanceManagerClientForTargets(ctx, runtimeParams, func(target target, client api.GadgetInstanceManagerClient) error {
		res, err := client.ListGadgetInstances(ctx, &api.ListGadgetInstancesRequest{})
		if err != nil {
			return err
		}

		// Merge results
		mu.Lock()
		instances = append(instances, res.GadgetInstances...)
		mu.Unlock()
		return nil
	})
	slices.SortFunc(instances, func(i1 *api.GadgetInstance, i2 *api.GadgetInstance) int {
		return strings.Compare(i1.Id, i2.Id)
	})
	instances = slices.CompactFunc(instances, func(i1 *api.GadgetInstance, i2 *api.GadgetInstance) bool {
		return i1.Id == i2.Id
	})
	return
}

func (r *Runtime) runInstanceManagerClientForTargets(ctx context.Context, runtimeParams *params.Params, fn func(target target, client api.GadgetInstanceManagerClient) error) error {
	// depending on the environment, we need to either connect to a single random target (k8s, where k8s/etcd handles
	// synchronizing gadget configuration), or all possible targets (ig-daemon).
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return fmt.Errorf("getting targets: %w", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets found")
	}

	if environment.Environment == environment.Kubernetes {
		// We only need to connect to one target
		targets = targets[:1]
	}

	var merr error
	var merrMutex sync.Mutex

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(target target) {
			defer wg.Done()
			conn, err := r.getConnFromTarget(ctx, runtimeParams, target)
			if err != nil {
				merrMutex.Lock()
				merr = multierror.Append(merr, fmt.Errorf("connecting to target %q: %w", target.node, err))
				merrMutex.Unlock()
				return
			}
			client := api.NewGadgetInstanceManagerClient(conn)
			err = fn(target, client)
			if err != nil {
				merrMutex.Lock()
				merr = multierror.Append(merr, fmt.Errorf("executing on target %q: %w", target.node, err))
				merrMutex.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return merr
}

func (r *Runtime) createGadgetInstance(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValues map[string]string) error {
	gadgetCtx.Logger().Debugf("creating gadget instance")

	var err error
	instanceID := runtimeParams.Get(ParamID).AsString()
	instanceName := runtimeParams.Get(ParamName).AsString()

	if instanceID != "" && !api.IsValidInstanceID(instanceID) {
		return fmt.Errorf("id must consist of 32 hexadecimal characters")
	}
	if instanceID == "" {
		instanceID, err = api.NewInstanceID()
		if err != nil {
			return fmt.Errorf("generating instance id: %w", err)
		}
	}

	if instanceName == "" {
		instanceName = namesgenerator.GetRandomName(0)
	}

	instanceRequest := &api.CreateGadgetInstanceRequest{
		GadgetInstance: &api.GadgetInstance{
			Id:   instanceID,
			Name: instanceName,
			Tags: strings.Split(runtimeParams.Get(ParamTags).AsString(), ","),
			GadgetConfig: &api.GadgetRunRequest{
				ImageName:   gadgetCtx.ImageName(),
				ParamValues: paramValues,
				Version:     api.VersionGadgetRunProtocol,
			},
		},
		EventBufferLength: runtimeParams.Get(ParamEventBufferLength).AsInt32(), // default for now
	}

	err = r.runInstanceManagerClientForTargets(gadgetCtx.Context(), runtimeParams, func(target target, client api.GadgetInstanceManagerClient) error {
		gadgetCtx.Logger().Debugf("creating gadget on node %q", target.node)
		res, err := client.CreateGadgetInstance(gadgetCtx.Context(), instanceRequest)
		if err != nil {
			return fmt.Errorf("creating gadget on node %q: %w", target.node, err)
		}
		gadgetCtx.Logger().Infof("installed on node %q as %q", target.node, res.GadgetInstance.Id)
		return nil
	})
	if err != nil {
		return fmt.Errorf("creating gadget instance: %w", err)
	}
	return nil
}
