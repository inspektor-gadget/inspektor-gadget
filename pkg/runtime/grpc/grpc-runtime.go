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
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/deployinfo"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type ConnectionMode int

const (
	ConnectionModeDirect ConnectionMode = iota
	ConnectionModeKubernetesProxy
)

const (
	ParamNode          = "node"
	ParamRemoteAddress = "remote-address"
	ParamDetach        = "detach"
	ParamName          = "name"
	ParamTags          = "tags"

	// ConnectTimeout is the time in seconds we wait for a connection to the pod to
	// succeed
	ConnectTimeout = 30

	// ResultTimeout is the time in seconds we wait for a result to return from the gadget
	// after sending a Stop command
	ResultTimeout = 30
)

type Runtime struct {
	info           *deployinfo.DeployInfo
	defaultValues  map[string]string
	globalParams   *params.Params
	connectionMode ConnectionMode
}

// New instantiates the runtime and loads the locally stored gadget info. If no info is stored locally,
// it will try to fetch one from one of the gadget nodes and store it locally. It will issue warnings on
// failures.
func New(options ...Option) *Runtime {
	r := &Runtime{
		defaultValues: map[string]string{},
	}
	for _, option := range options {
		option(r)
	}
	return r
}

// InitInfo loads the locally stored gadget catalog. If no catalog is stored locally,
// it will try to fetch one from one of the gadget nodes and store it locally. It will issue warnings on
// failures.
func (r *Runtime) InitInfo(globalParams *params.Params) error {
	// Initialize info
	info, err := deployinfo.Load()
	if err == nil {
		r.info = info
		return nil
	}

	info, err = r.loadRemoteDeployInfo(globalParams)
	if err != nil {
		log.Warnf("could not load gadget info from remote: %v", err)
		return nil
	}
	r.info = info

	err = deployinfo.Store(info)
	if err != nil {
		log.Warnf("could not store gadget info: %v", err)
	}

	return nil
}

func (r *Runtime) UpdateDeployInfo() error {
	info, err := r.loadRemoteDeployInfo(r.globalParams)
	if err != nil {
		return fmt.Errorf("loading remote gadget info: %w", err)
	}

	return deployinfo.Store(info)
}

func (r *Runtime) Init(runtimeGlobalParams *params.Params) error {
	r.globalParams = runtimeGlobalParams
	return nil
}

func (r *Runtime) Close() error {
	return nil
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	p := params.ParamDescs{
		{
			Key:          ParamDetach,
			Description:  "Keep gadget running in the background",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:          ParamName,
			Description:  "Assign a distinctive name to this gadget instance",
			TypeHint:     params.TypeString,
			DefaultValue: "",
		},
		{
			Key:         ParamTags,
			Description: "List of comma-separated tags to assign to this instance",
			TypeHint:    params.TypeString,
		},
	}
	switch r.connectionMode {
	case ConnectionModeDirect:
		p.Add(params.ParamDescs{
			{
				Key:          ParamRemoteAddress,
				Description:  "Comma-separated list of remote address (gRPC) to connect to",
				DefaultValue: "unix:///var/run/ig.socket",
			},
		}...)
		return p
	case ConnectionModeKubernetesProxy:
		p.Add(params.ParamDescs{
			{
				Key:         ParamNode,
				Description: "Comma-separated list of nodes to run the gadget on",
				Validator: func(value string) error {
					nodes := strings.Split(value, ",")
					nodeMap := make(map[string]struct{})
					for _, node := range nodes {
						if _, ok := nodeMap[node]; ok {
							return fmt.Errorf("duplicated node: %s", node)
						}
						nodeMap[node] = struct{}{}
					}
					return nil
				},
			},
		}...)
		return p
	}
	panic("invalid connection mode set for grpc-runtime")
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	return nil
}

type target struct {
	name string
	node string
}

func getGadgetPods(ctx context.Context, nodes []string) ([]target, error) {
	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("creating RESTConfig: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("setting up trace client: %w", err)
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods("gadget").List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("getting pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no gadget pods found. Is Inspektor Gadget deployed?")
	}

	if len(nodes) == 0 {
		res := make([]target, 0, len(pods.Items))

		for _, pod := range pods.Items {
			res = append(res, target{name: pod.Name, node: pod.Spec.NodeName})
		}

		return res, nil
	}

	res := make([]target, 0, len(nodes))
nodesLoop:
	for _, node := range nodes {
		for _, pod := range pods.Items {
			if node == pod.Spec.NodeName {
				res = append(res, target{name: pod.Name, node: node})
				continue nodesLoop
			}
		}
		return nil, fmt.Errorf("node %q does not have a gadget pod", node)
	}

	return res, nil
}

func (r *Runtime) getTargets(ctx context.Context, params *params.Params) ([]target, error) {
	switch r.connectionMode {
	case ConnectionModeKubernetesProxy:
		// Get nodes to run on
		nodes := params.Get(ParamNode).AsStringSlice()
		pods, err := getGadgetPods(ctx, nodes)
		if err != nil {
			return nil, fmt.Errorf("get gadget pods: %w", err)
		}
		if len(pods) == 0 {
			return nil, fmt.Errorf("get gadget pods: Inspektor Gadget is not running on the requested node(s): %v", nodes) //nolint:all
		}
		return pods, nil
	case ConnectionModeDirect:
		inTargets := params.Get(ParamRemoteAddress).AsStringSlice()
		targets := make([]target, 0)
		for _, t := range inTargets {
			purl, err := url.Parse(t)
			if err != nil {
				return nil, fmt.Errorf("invalid remote address %q: %w", t, err)
			}
			targets = append(targets, target{
				name: t,
				node: purl.Hostname(),
			})
		}
		return targets, nil
	}
	return nil, fmt.Errorf("unsupported connection mode")
}

func (r *Runtime) RunGadget(gadgetCtx runtime.GadgetContext) (runtime.CombinedGadgetResult, error) {
	paramMap := make(map[string]string)
	gadgets.ParamsToMap(
		paramMap,
		gadgetCtx.GadgetParams(),
		gadgetCtx.RuntimeParams(),
		gadgetCtx.OperatorsParamCollection(),
	)

	gadgetCtx.Logger().Debugf("Params")
	for k, v := range paramMap {
		gadgetCtx.Logger().Debugf("- %s: %q", k, v)
	}

	targets, err := r.getTargets(gadgetCtx.Context(), gadgetCtx.RuntimeParams())
	if err != nil {
		return nil, fmt.Errorf("getting target nodes: %w", err)
	}
	return r.runGadgetOnTargets(gadgetCtx, paramMap, targets)
}

func (r *Runtime) getClientFromRandomTarget(ctx context.Context, runtimeParams *params.Params) (api.GadgetManagerClient, error) {
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}
	conn, err := r.dialContext(ctx, targets[0])
	if err != nil {
		return nil, err
	}
	client := api.NewGadgetManagerClient(conn)
	return client, nil
}

func (r *Runtime) RemovePersistentGadget(ctx context.Context, runtimeParams *params.Params, id string) error {
	client, err := r.getClientFromRandomTarget(ctx, runtimeParams)
	if err != nil {
		return err
	}
	res, err := client.RemovePersistentGadget(ctx, &api.PersistentGadgetId{Id: id})
	if err != nil {
		return err
	}
	if res.Result != 0 {
		return errors.New(res.Message)
	}
	return nil
}

func (r *Runtime) StopPersistentGadget(ctx context.Context, runtimeParams *params.Params, id string) error {
	client, err := r.getClientFromRandomTarget(ctx, runtimeParams)
	if err != nil {
		return err
	}
	res, err := client.StopPersistentGadget(ctx, &api.PersistentGadgetId{Id: id})
	if err != nil {
		return err
	}
	if res.Result != 0 {
		return errors.New(res.Message)
	}
	return nil
}

func (r *Runtime) GetPersistentGadgets(ctx context.Context, runtimeParams *params.Params) ([]*api.PersistentGadget, error) {
	client, err := r.getClientFromRandomTarget(ctx, runtimeParams)
	if err != nil {
		return nil, err
	}
	res, err := client.ListPersistentGadgets(ctx, &api.ListPersistentGadgetRequest{})
	if err != nil {
		return nil, err
	}
	return res.PersistentGadgets, nil
}

func (r *Runtime) installPersistent(gadgetCtx runtime.GadgetContext, paramMap map[string]string, targets []target) error {
	gadgetCtx.Logger().Debugf("installing persistent gadget")

	dialCtx, cancelDial := context.WithTimeout(gadgetCtx.Context(), time.Second*ConnectTimeout)
	defer cancelDial()

	target := targets[0]

	conn, err := r.dialContext(dialCtx, target)
	if err != nil {
		return fmt.Errorf("dialing node %q: %w", target.node, err)
	}
	defer conn.Close()
	client := api.NewGadgetManagerClient(conn)

	res, err := client.InstallPersistentGadget(dialCtx, &api.InstallPersistentGadgetRequest{
		PersistentGadget: &api.PersistentGadget{
			Name: gadgetCtx.RuntimeParams().Get(ParamName).AsString(),
			Tags: strings.Split(gadgetCtx.RuntimeParams().Get(ParamTags).AsString(), ","),
			GadgetInfo: &api.GadgetRunRequest{
				GadgetName:     gadgetCtx.GadgetDesc().Name(),
				GadgetCategory: gadgetCtx.GadgetDesc().Category(),
				Params:         paramMap,
			},
		},
		EventBufferLength: 0,
	})
	if err != nil {
		return err
	}

	gadgetCtx.Logger().Debugf("installed as %q", res.PersistentGadget.Id)
	return nil
}

func (r *Runtime) runGadgetOnTargets(
	gadgetCtx runtime.GadgetContext,
	paramMap map[string]string,
	targets []target,
) (runtime.CombinedGadgetResult, error) {
	isPersistent := gadgetCtx.RuntimeParams().Get(ParamDetach).AsBool()
	if isPersistent {
		// Add on first node only
		err := r.installPersistent(gadgetCtx, paramMap, targets)
		if err != nil {
			return nil, fmt.Errorf("could not install persistent gadget: %w", err)
		}
		// if not in interactive mode, return here
		return nil, nil
	}

	if gadgetCtx.GadgetDesc().Type() == gadgets.TypeTraceIntervals {
		gadgetCtx.Parser().EnableSnapshots(
			gadgetCtx.Context(),
			time.Duration(gadgetCtx.GadgetParams().Get(gadgets.ParamInterval).AsInt32())*time.Second,
			2,
		)
		defer gadgetCtx.Parser().Flush()
	}

	if gadgetCtx.GadgetDesc().Type() == gadgets.TypeOneShot {
		gadgetCtx.Parser().EnableCombiner()
		defer gadgetCtx.Parser().Flush()
	}

	results := make(runtime.CombinedGadgetResult)
	var resultsLock sync.Mutex

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			gadgetCtx.Logger().Debugf("running gadget on node %q", t.node)
			res, err := r.runGadget(gadgetCtx, t, paramMap)
			resultsLock.Lock()
			results[t.node] = &runtime.GadgetResult{
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

func (r *Runtime) dialContext(dialCtx context.Context, target target) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	// If we're in Kubernetes connection mode, we need a custom dialer
	if r.connectionMode == ConnectionModeKubernetesProxy {
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return NewK8SExecConn(ctx, target, time.Second*ConnectTimeout)
		}))
	}

	conn, err := grpc.DialContext(dialCtx, "passthrough:///"+target.name, opts...)
	if err != nil {
		return nil, fmt.Errorf("dialing node %q: %w", target.node, err)
	}
	return conn, nil
}

type RunClient interface {
	Recv() (*api.GadgetEvent, error)
}

func (r *Runtime) runGadget(
	gadgetCtx runtime.GadgetContext,
	pod target,
	allParams map[string]string,
) ([]byte, error) {
	// Notice that we cannot use gadgetCtx.Context() here, as that would - when cancelled by the user - also cancel the
	// underlying gRPC connection. That would then lead to results not being received anymore (mostly for profile
	// gadgets.)
	connCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialCtx, cancelDial := context.WithTimeout(gadgetCtx.Context(), time.Second*ConnectTimeout)
	defer cancelDial()

	conn, err := r.dialContext(dialCtx, pod)
	if err != nil {
		return nil, fmt.Errorf("dialing gadget pod on node %q: %w", pod.node, err)
	}
	defer conn.Close()
	client := api.NewGadgetManagerClient(conn)

	runRequest := &api.GadgetRunRequest{
		GadgetName:     gadgetCtx.GadgetDesc().Name(),
		GadgetCategory: gadgetCtx.GadgetDesc().Category(),
		Params:         allParams,
		Nodes:          nil,
		FanOut:         false,
		LogLevel:       uint32(gadgetCtx.Logger().GetLevel()),
		Timeout:        int64(gadgetCtx.Timeout()),
	}

	var runClient RunClient

	if gadgetCtx.ID() != "" {
		gadgetCtx.Logger().Debugf("attaching to existing gadget %q", gadgetCtx.ID())
		grpcClient, err := client.AttachToPersistentGadget(connCtx, &api.PersistentGadgetId{Id: gadgetCtx.ID()})
		if err != nil && !errors.Is(err, context.Canceled) {
			return nil, err
		}
		runClient = grpcClient
	} else {
		gadgetCtx.Logger().Debugf("starting new gadget %q")
		grpcClient, err := client.RunGadget(connCtx)
		if err != nil && !errors.Is(err, context.Canceled) {
			return nil, err
		}
		controlRequest := &api.GadgetControlRequest{Event: &api.GadgetControlRequest_RunRequest{RunRequest: runRequest}}
		err = grpcClient.Send(controlRequest)
		if err != nil {
			return nil, err
		}
		runClient = grpcClient
	}

	parser := gadgetCtx.Parser()

	jsonHandler := func([]byte) {}
	jsonArrayHandler := func([]byte) {}

	if parser != nil {
		var enrichers []func(any) error
		ev := gadgetCtx.GadgetDesc().EventPrototype()
		if _, ok := ev.(operators.NodeSetter); ok {
			enrichers = append(enrichers, func(ev any) error {
				ev.(operators.NodeSetter).SetNode(pod.node)
				return nil
			})
		}

		jsonHandler = parser.JSONHandlerFunc(enrichers...)
		jsonArrayHandler = parser.JSONHandlerFuncArray(pod.node, enrichers...)
	}

	doneChan := make(chan error)

	var result []byte
	expectedSeq := uint32(1)

	go func() {
		for {
			ev, err := runClient.Recv()
			if err != nil {
				gadgetCtx.Logger().Debugf("%-20s | runClient returned with %v", pod.node, err)
				if !errors.Is(err, io.EOF) {
					doneChan <- err
					return
				}
				doneChan <- nil
				return
			}
			switch ev.Type {
			case api.EventTypeGadgetPayload:
				if expectedSeq != ev.Seq {
					gadgetCtx.Logger().Warnf("%-20s | expected seq %d, got %d, %d messages dropped", pod.node, expectedSeq, ev.Seq, ev.Seq-expectedSeq)
				}
				expectedSeq = ev.Seq + 1
				if len(ev.Payload) > 0 && ev.Payload[0] == '[' {
					jsonArrayHandler(ev.Payload)
					continue
				}
				jsonHandler(ev.Payload)
			case api.EventTypeGadgetResult:
				gadgetCtx.Logger().Debugf("%-20s | got result from server", pod.node)
				result = ev.Payload
			case api.EventTypeGadgetJobID: // not needed right now
			default:
				if ev.Type >= 1<<api.EventLogShift {
					gadgetCtx.Logger().Log(logger.Level(ev.Type>>api.EventLogShift), fmt.Sprintf("%-20s | %s", pod.node, string(ev.Payload)))
					continue
				}
				gadgetCtx.Logger().Warnf("unknown payload type %d: %s", ev.Type, ev.Payload)
			}
		}
	}()

	var runErr error
	select {
	case doneErr := <-doneChan:
		gadgetCtx.Logger().Debugf("%-20s | done from server side (%v)", pod.node, doneErr)
		runErr = doneErr
	case <-gadgetCtx.Context().Done():
		// Send stop request
		if t, ok := runClient.(api.GadgetManager_RunGadgetClient); ok {
			gadgetCtx.Logger().Debugf("%-20s | sending stop request", pod.node)
			controlRequest := &api.GadgetControlRequest{Event: &api.GadgetControlRequest_StopRequest{StopRequest: &api.GadgetStopRequest{}}}
			// Only send stop command when not attached
			t.Send(controlRequest)

			// Wait for done or timeout
			select {
			case doneErr := <-doneChan:
				gadgetCtx.Logger().Debugf("%-20s | done after cancel request (%v)", pod.node, doneErr)
				runErr = doneErr
			case <-time.After(ResultTimeout * time.Second):
				return nil, fmt.Errorf("timed out while getting result")
			}
		}
	}
	return result, runErr
}

func (r *Runtime) GetCatalog() (*runtime.Catalog, error) {
	if r.info == nil {
		return nil, nil
	}
	return r.info.Catalog, nil
}

func (r *Runtime) SetDefaultValue(key params.ValueHint, value string) {
	r.defaultValues[strings.ToLower(string(key))] = value
}

func (r *Runtime) GetDefaultValue(key params.ValueHint) (string, bool) {
	val, ok := r.defaultValues[strings.ToLower(string(key))]
	return val, ok
}
