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

	"github.com/moby/moby/pkg/namesgenerator"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type GadgetInstance struct {
	Instance *api.GadgetInstance
	Node     string
}

func (r *Runtime) RemoveGadgetInstance(ctx context.Context, runtimeParams *params.Params, id string) error {
	return r.runInstanceManagerClientForTargets(ctx, runtimeParams, false, func(target target, client api.GadgetInstanceManagerClient) error {
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

func (r *Runtime) GetGadgetInstances(ctx context.Context, runtimeParams *params.Params, state bool) (instances []*GadgetInstance, err error) {
	var mu sync.Mutex
	err = r.runInstanceManagerClientForTargets(ctx, runtimeParams, state, func(target target, client api.GadgetInstanceManagerClient) error {
		res, err := client.ListGadgetInstances(ctx, &api.ListGadgetInstancesRequest{})
		if err != nil {
			return err
		}

		// Merge results
		mu.Lock()
		for _, gi := range res.GadgetInstances {
			instances = append(instances, &GadgetInstance{
				Instance: gi,
				Node:     target.node,
			})
		}
		mu.Unlock()
		return nil
	})
	slices.SortFunc(instances, func(i1 *GadgetInstance, i2 *GadgetInstance) int {
		if cmp := strings.Compare(i1.Instance.Id, i2.Instance.Id); cmp != 0 {
			return cmp
		}
		return strings.Compare(i1.Node, i2.Node)
	})
	if !state {
		instances = slices.CompactFunc(instances, func(i1 *GadgetInstance, i2 *GadgetInstance) bool {
			return i1.Instance.Id == i2.Instance.Id
		})
	}
	return
}

func (r *Runtime) runInstanceManagerClientForTargets(ctx context.Context, runtimeParams *params.Params, state bool, fn func(target target, client api.GadgetInstanceManagerClient) error) error {
	// depending on the environment, we need to either connect to a single random target (k8s, where k8s/etcd handles
	// synchronizing gadget configuration), or all possible targets (ig-daemon).
	// if state is true, we always need to connect to all targets to get the full state
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return fmt.Errorf("getting targets: %w", err)
	}

	if len(targets) == 0 {
		return fmt.Errorf("no targets found")
	}

	if !state && environment.Environment == environment.Kubernetes {
		// We only need to connect to one target
		targets = targets[:1]
	}

	var errs []error
	var merrMutex sync.Mutex

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(target target) {
			defer wg.Done()
			conn, err := r.getConnFromTarget(ctx, runtimeParams, target)
			if err != nil {
				merrMutex.Lock()
				errs = append(errs, fmt.Errorf("connecting to target %q: %w", target.node, err))
				merrMutex.Unlock()
				return
			}
			client := api.NewGadgetInstanceManagerClient(conn)
			err = fn(target, client)
			if err != nil {
				merrMutex.Lock()
				errs = append(errs, fmt.Errorf("executing on target %q: %w", target.node, err))
				merrMutex.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return errors.Join(errs...)
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

	// if targets have explicitly been listed, add them to the `Nodes` list
	if paramNode := runtimeParams.Get(ParamNode); paramNode != nil {
		instanceRequest.GadgetInstance.Nodes = paramNode.AsStringSlice()
	}

	var listMutex sync.Mutex
	var nodeList []string
	ids := make(map[string][]string)
	var lastID string

	err = r.runInstanceManagerClientForTargets(gadgetCtx.Context(), runtimeParams, false, func(target target, client api.GadgetInstanceManagerClient) error {
		gadgetCtx.Logger().Debugf("creating gadget on node %q", target.node)
		res, err := client.CreateGadgetInstance(gadgetCtx.Context(), instanceRequest)
		if err != nil {
			return fmt.Errorf("creating gadget on node %q: %w", target.node, err)
		}
		listMutex.Lock()
		nodeList = append(nodeList, target.node)
		ids[res.GadgetInstance.Id] = append(ids[res.GadgetInstance.Id], target.node)
		lastID = res.GadgetInstance.Id
		listMutex.Unlock()
		return nil
	})
	if err != nil {
		return fmt.Errorf("creating gadget instance: %w", err)
	}

	if len(ids) > 1 {
		// this can only happen if the server refused to use the given id (which should not happen with the current
		// implementations) and we're deploying on multiple targets where each target would choose its own id
		for k, v := range ids {
			gadgetCtx.Logger().Infof("installed as %q (nodes %+v)", k, v)
		}
		return nil
	}

	gadgetCtx.Logger().Infof("installed as %q", lastID)
	return nil
}
