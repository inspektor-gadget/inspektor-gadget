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

package grpcruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

func (r *Runtime) GetGadgetInfo(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValues api.ParamValues) (*api.GadgetInfo, error) {
	if runtimeParams == nil {
		runtimeParams = r.ParamDescs().ToParams()
	}

	conn, err := r.getConnToRandomTarget(gadgetCtx.Context(), runtimeParams)
	if err != nil {
		return nil, fmt.Errorf("dialing random target: %w", err)
	}
	defer conn.Close()
	client := api.NewGadgetManagerClient(conn)

	in := &api.GetGadgetInfoRequest{
		ParamValues: paramValues,
		ImageName:   gadgetCtx.ImageName(),
		Version:     api.VersionGadgetInfo,
	}
	out, err := client.GetGadgetInfo(gadgetCtx.Context(), in)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}

	err = gadgetCtx.LoadGadgetInfo(out.GadgetInfo, paramValues, false)
	if err != nil {
		return nil, fmt.Errorf("initializing local operators: %w", err)
	}

	return gadgetCtx.SerializeGadgetInfo()
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext, runtimeParams *params.Params, paramValues api.ParamValues) error {
	if runtimeParams == nil {
		runtimeParams = r.ParamDescs().ToParams()
	}

	gadgetCtx.Logger().Debugf("Params")
	for k, v := range paramValues {
		gadgetCtx.Logger().Debugf("- %s: %q", k, v)
	}

	if runtimeParams.Get(ParamDetachable).AsBool() {
		return r.installGadgetInstance(gadgetCtx, runtimeParams, paramValues)
	}

	targets, err := r.getTargets(gadgetCtx.Context(), runtimeParams)
	if err != nil {
		return fmt.Errorf("getting target nodes: %w", err)
	}
	_, err = r.runGadgetOnTargets(gadgetCtx, paramValues, targets)
	return err
}

func (r *Runtime) runGadgetOnTargets(
	gadgetCtx runtime.GadgetContext,
	paramMap map[string]string,
	targets []target,
) (runtime.CombinedGadgetResult, error) {
	results := make(runtime.CombinedGadgetResult, len(targets))
	var resultsLock sync.Mutex

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(target target) {
			gadgetCtx.Logger().Debugf("running gadget on node %q", target.node)
			res, err := r.runGadget(gadgetCtx, target, paramMap)
			resultsLock.Lock()
			results[target.node] = &runtime.GadgetResult{
				Payload: res,
				Error:   err,
			}
			resultsLock.Unlock()
			wg.Done()
		}(t)
	}

	wg.Wait()
	return results, results.Err()
}

func (r *Runtime) runGadget(gadgetCtx runtime.GadgetContext, target target, allParams map[string]string) ([]byte, error) {
	// Notice that we cannot use gadgetCtx.Context() here, as that would - when cancelled by the user - also cancel the
	// underlying gRPC connection. That would then lead to results not being received anymore (mostly for profile
	// gadgets.)
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	timeout := time.Second * time.Duration(r.globalParams.Get(ParamConnectionTimeout).AsUint16())
	dialCtx, cancelDial := context.WithTimeout(gadgetCtx.Context(), timeout)
	defer cancelDial()

	conn, err := r.dialContext(dialCtx, target, timeout)
	if err != nil {
		return nil, fmt.Errorf("dialing target on node %q: %w", target.node, err)
	}
	defer conn.Close()
	client := api.NewGadgetManagerClient(conn)

	runClient, err := client.RunGadget(connCtx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	var controlRequest *api.GadgetControlRequest

	interactive := true
	if id, ok := strings.CutPrefix(gadgetCtx.ImageName(), "attach://"); ok {
		gadgetCtx.Logger().Debugf("attaching to gadget %s", id)
		controlRequest = &api.GadgetControlRequest{
			Event: &api.GadgetControlRequest_AttachRequest{
				AttachRequest: &api.GadgetAttachRequest{
					Id: id,
				},
			},
		}
		interactive = false
	} else {
		controlRequest = &api.GadgetControlRequest{
			Event: &api.GadgetControlRequest_RunRequest{
				RunRequest: &api.GadgetRunRequest{
					ImageName:   gadgetCtx.ImageName(),
					ParamValues: allParams,
					Args:        gadgetCtx.Args(),
					LogLevel:    uint32(gadgetCtx.Logger().GetLevel()),
					Timeout:     int64(gadgetCtx.Timeout()),
					Version:     api.VersionGadgetRunProtocol,
				},
			},
		}
	}

	err = runClient.Send(controlRequest)
	if err != nil {
		return nil, err
	}

	doneChan := make(chan error)

	var result []byte
	expectedSeq := uint32(1)

	go func() {
		dsMap := make(map[uint32]datasource.DataSource)
		dsNameMap := make(map[string]uint32)
		initialized := false
		for {
			ev, err := runClient.Recv()
			if err != nil {
				gadgetCtx.Logger().Debugf("%-20s | runClient returned with %v", target.node, err)
				if !errors.Is(err, io.EOF) {
					doneChan <- err
					return
				}
				doneChan <- nil
				return
			}
			switch ev.Type {
			case api.EventTypeGadgetPayload:
				if !initialized {
					gadgetCtx.Logger().Warnf("%-20s | received payload without being initialized", target.node)
					continue
				}
				if expectedSeq != ev.Seq {
					gadgetCtx.Logger().Warnf("%-20s | expected seq %d, got %d, %d messages dropped", target.node, expectedSeq, ev.Seq, ev.Seq-expectedSeq)
				}
				expectedSeq = ev.Seq + 1
				if ds, ok := dsMap[ev.DataSourceID]; ok && ds != nil {
					var p datasource.Packet
					switch ds.Type() {
					case datasource.TypeSingle:
						p, err = ds.NewPacketSingleFromRaw(ev.Payload)
					case datasource.TypeArray:
						p, err = ds.NewPacketArrayFromRaw(ev.Payload)
					default:
						gadgetCtx.Logger().Warnf("unknown datasource type %d", ds.Type())
						continue
					}
					if err != nil {
						gadgetCtx.Logger().Debugf("error unmarshaling payload: %v", err)
						continue
					}
					ds.EmitAndRelease(p)
				}
			case api.EventTypeGadgetResult:
				gadgetCtx.Logger().Debugf("%-20s | got result from server", target.node)
				result = ev.Payload
			case api.EventTypeGadgetJobID: // not needed right now
			case api.EventTypeGadgetInfo:
				gi := &api.GadgetInfo{}
				err = proto.Unmarshal(ev.Payload, gi)
				if err != nil {
					gadgetCtx.Logger().Warnf("unmarshaling gadget info: %v", err)
					continue
				}
				for _, ds := range gi.DataSources {
					dsNameMap[ds.Name] = ds.Id
				}

				// Try to load gadget info; if gadget info has already been loaded and this one
				// doesn't match, this will terminate this particular client session
				err = gadgetCtx.LoadGadgetInfo(gi, allParams, true)
				if err != nil {
					gadgetCtx.Logger().Warnf("deserizalize gadget info: %v", err)
					continue
				}
				gadgetCtx.Logger().Debugf("loaded gadget info")
				for _, ds := range gadgetCtx.GetDataSources() {
					gadgetCtx.Logger().Debugf("registered ds %s", ds.Name())
					dsMap[dsNameMap[ds.Name()]] = ds
				}
				initialized = true
			default:
				if ev.Type >= 1<<api.EventLogShift {
					gadgetCtx.Logger().Log(logger.Level(ev.Type>>api.EventLogShift), fmt.Sprintf("%-20s | %s", target.node, string(ev.Payload)))
					continue
				}
				gadgetCtx.Logger().Warnf("unknown payload type %d: %s", ev.Type, ev.Payload)
			}
		}
	}()

	var runErr error
	select {
	case doneErr := <-doneChan:
		gadgetCtx.Logger().Debugf("%-20s | done from server side (%v)", target.node, doneErr)
		runErr = doneErr
	case <-gadgetCtx.Context().Done():
		if interactive {
			// Send stop request
			gadgetCtx.Logger().Debugf("%-20s | sending stop request", target.node)
			controlRequest := &api.GadgetControlRequest{Event: &api.GadgetControlRequest_StopRequest{StopRequest: &api.GadgetStopRequest{}}}
			runClient.Send(controlRequest)

			// Wait for done or timeout
			select {
			case doneErr := <-doneChan:
				gadgetCtx.Logger().Debugf("%-20s | done after cancel request (%v)", target.node, doneErr)
				runErr = doneErr
			case <-time.After(ResultTimeout * time.Second):
				return nil, fmt.Errorf("timed out while getting result")
			}
		}
	}
	return result, runErr
}
