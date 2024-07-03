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
	"k8s.io/client-go/rest"

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
	// ConnectionModeDirect will connect directly to the remote using the gRPC protocol; the remote side can either
	// be a tcp or a unix socket endpoint
	ConnectionModeDirect ConnectionMode = iota

	// ConnectionModeKubernetesProxy will connect to a gRPC endpoint through a kubernetes API server by first looking
	// up an appropriate target node using the kubernetes API, then using the port forward
	// endpoint of the Kubernetes API to forward the gRPC connection to the service listener (see gadgettracermgr).
	ConnectionModeKubernetesProxy
)

const (
	ParamNode              = "node"
	ParamRemoteAddress     = "remote-address"
	ParamConnectionMethod  = "connection-method"
	ParamConnectionTimeout = "connection-timeout"
	ParamDetachable        = "detachable"
	ParamInstallOnly       = "install-only"
	ParamTags              = "tags"
	ParamName              = "name"

	// ParamGadgetServiceTCPPort is only used in combination with KubernetesProxyConnectionMethodTCP
	ParamGadgetServiceTCPPort = "tcp-port"

	// ConnectTimeout is the time in seconds we wait for a connection to the remote to
	// succeed
	ConnectTimeout = 5

	// ResultTimeout is the time in seconds we wait for a result to return from the gadget
	// after sending a Stop command
	ResultTimeout = 30

	ParamGadgetNamespace   string = "gadget-namespace"
	DefaultGadgetNamespace string = "gadget"
)

type Runtime struct {
	info           *deployinfo.DeployInfo
	defaultValues  map[string]string
	globalParams   *params.Params
	restConfig     *rest.Config
	connectionMode ConnectionMode
}

type RunClient interface {
	Recv() (*api.GadgetEvent, error)
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

func (r *Runtime) Init(runtimeGlobalParams *params.Params) error {
	if runtimeGlobalParams == nil {
		runtimeGlobalParams = r.GlobalParamDescs().ToParams()
	}

	// overwrite only if not yet initialized; for gadgetctl, this initialization happens
	// already in the main.go to specify a target address
	if r.globalParams == nil {
		r.globalParams = runtimeGlobalParams
	}
	return nil
}

func (r *Runtime) SetRestConfig(config *rest.Config) {
	r.restConfig = config
}

func (r *Runtime) Close() error {
	return nil
}

func checkForDuplicates(subject string) func(value string) error {
	return func(value string) error {
		values := strings.Split(value, ",")
		valueMap := make(map[string]struct{})
		for _, v := range values {
			if _, ok := valueMap[v]; ok {
				return fmt.Errorf("duplicate %s: %s", subject, v)
			}
			valueMap[v] = struct{}{}
		}
		return nil
	}
}

func (r *Runtime) ParamDescs() params.ParamDescs {
	p := params.ParamDescs{
		{
			Key:          ParamDetachable,
			Description:  "Install gadget to be able to attach to it from multiple clients and keep it running in the background",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:          ParamInstallOnly,
			Description:  "Install gadget without directly attaching to it",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:         ParamTags,
			Description: "Comma-separated list of tags to apply to the gadget instance",
			TypeHint:    params.TypeString,
		},
		{
			Key:         ParamName,
			Description: "Distinctive name to assign to the gadget instance",
			TypeHint:    params.TypeString,
		},
	}
	switch r.connectionMode {
	case ConnectionModeDirect:
		return p
	case ConnectionModeKubernetesProxy:
		p.Add(params.ParamDescs{
			{
				Key:         ParamNode,
				Description: "Comma-separated list of nodes to run the gadget on",
				Validator:   checkForDuplicates("node"),
			},
		}...)
		return p
	}
	panic("invalid connection mode set for grpc-runtime")
}

func (r *Runtime) GlobalParamDescs() params.ParamDescs {
	p := params.ParamDescs{
		{
			Key:          ParamConnectionTimeout,
			Description:  "Maximum time to establish a connection to remote target in seconds",
			DefaultValue: fmt.Sprintf("%d", ConnectTimeout),
			TypeHint:     params.TypeUint16,
		},
	}
	switch r.connectionMode {
	case ConnectionModeDirect:
		p.Add(params.ParamDescs{
			{
				Key:          ParamRemoteAddress,
				Description:  "Comma-separated list of remote address (gRPC) to connect to",
				DefaultValue: api.DefaultDaemonPath,
				Validator:    checkForDuplicates("address"),
			},
		}...)
		return p
	case ConnectionModeKubernetesProxy:
		p.Add(params.ParamDescs{
			{
				Key:          ParamGadgetServiceTCPPort,
				Description:  "Port used to connect to the gadget service",
				DefaultValue: fmt.Sprintf("%d", api.GadgetServicePort),
				TypeHint:     params.TypeUint16,
			},
			{
				Key:          ParamGadgetNamespace,
				Description:  "Namespace where the Inspektor Gadget is deployed",
				DefaultValue: DefaultGadgetNamespace,
				TypeHint:     params.TypeString,
			},
		}...)
		return p
	}
	panic("invalid connection mode set for grpc-runtime")
}

type target struct {
	addressOrPod string
	node         string
}

func getGadgetPods(ctx context.Context, config *rest.Config, nodes []string, gadgetNamespace string) ([]target, error) {
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("setting up trace client: %w", err)
	}

	opts := metav1.ListOptions{LabelSelector: "k8s-app=gadget"}
	pods, err := client.CoreV1().Pods(gadgetNamespace).List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("getting pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return nil, fmt.Errorf("no gadget pods found in namespace %q. Is Inspektor Gadget deployed?", gadgetNamespace)
	}

	if len(nodes) == 0 {
		res := make([]target, 0, len(pods.Items))

		for _, pod := range pods.Items {
			res = append(res, target{addressOrPod: pod.Name, node: pod.Spec.NodeName})
		}

		return res, nil
	}

	res := make([]target, 0, len(nodes))
nodesLoop:
	for _, node := range nodes {
		for _, pod := range pods.Items {
			if node == pod.Spec.NodeName {
				res = append(res, target{addressOrPod: pod.Name, node: node})
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
		gadgetNamespace := r.globalParams.Get(ParamGadgetNamespace).AsString()
		pods, err := getGadgetPods(ctx, r.restConfig, nodes, gadgetNamespace)
		if err != nil {
			return nil, fmt.Errorf("get gadget pods: %w", err)
		}
		if len(pods) == 0 {
			return nil, fmt.Errorf("get gadget pods: Inspektor Gadget is not running on the requested node(s): %v", nodes)
		}
		return pods, nil
	case ConnectionModeDirect:
		inTargets := r.globalParams.Get(ParamRemoteAddress).AsStringSlice()
		targets := make([]target, 0)
		for _, t := range inTargets {
			purl, err := url.Parse(t)
			if err != nil {
				return nil, fmt.Errorf("invalid remote address %q: %w", t, err)
			}
			tg := target{
				addressOrPod: purl.Host,
				node:         purl.Hostname(),
			}
			if purl.Scheme == "unix" {
				// use the whole url in case of a unix socket and "local" as node
				tg.addressOrPod = t
				tg.node = "local"
			}
			targets = append(targets, tg)
		}
		return targets, nil
	}
	return nil, fmt.Errorf("unsupported connection mode")
}

func (r *Runtime) RunBuiltInGadget(gadgetCtx runtime.GadgetContext) (runtime.CombinedGadgetResult, error) {
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
	return r.runBuiltInGadgetOnTargets(gadgetCtx, paramMap, targets)
}

func (r *Runtime) getConnToRandomTarget(ctx context.Context, runtimeParams *params.Params) (*grpc.ClientConn, error) {
	targets, err := r.getTargets(ctx, runtimeParams)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}
	target := targets[0]
	log.Debugf("using target %q (%q)", target.addressOrPod, target.node)

	timeout := time.Second * time.Duration(r.globalParams.Get(ParamConnectionTimeout).AsUint16())
	conn, err := r.dialContext(ctx, target, timeout)
	if err != nil {
		return nil, fmt.Errorf("dialing %q (%q): %w", target.addressOrPod, target.node, err)
	}
	return conn, nil
}

func (r *Runtime) runBuiltInGadgetOnTargets(
	gadgetCtx runtime.GadgetContext,
	paramMap map[string]string,
	targets []target,
) (runtime.CombinedGadgetResult, error) {
	gType := gadgetCtx.GadgetDesc().Type()

	if gType == gadgets.TypeTraceIntervals {
		gadgetCtx.Parser().EnableSnapshots(
			gadgetCtx.Context(),
			time.Duration(gadgetCtx.GadgetParams().Get(gadgets.ParamInterval).AsInt32())*time.Second,
			2,
		)
		defer gadgetCtx.Parser().Flush()
	}

	if gType == gadgets.TypeOneShot {
		gadgetCtx.Parser().EnableCombiner()
		defer gadgetCtx.Parser().Flush()
	}

	results := make(runtime.CombinedGadgetResult)
	var resultsLock sync.Mutex

	wg := sync.WaitGroup{}
	for _, t := range targets {
		wg.Add(1)
		go func(target target) {
			gadgetCtx.Logger().Debugf("running gadget on node %q", target.node)
			res, err := r.runBuiltInGadget(gadgetCtx, target, paramMap)
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

func (r *Runtime) dialContext(dialCtx context.Context, target target, timeout time.Duration) (*grpc.ClientConn, error) {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	}

	// If we're in Kubernetes connection mode, we need a custom dialer
	if r.connectionMode == ConnectionModeKubernetesProxy {
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			port := r.globalParams.Get(ParamGadgetServiceTCPPort).AsUint16()
			gadgetNamespace := r.globalParams.Get(ParamGadgetNamespace).AsString()
			return NewK8SPortFwdConn(ctx, r.restConfig, gadgetNamespace, target, port, timeout)
		}))
	} else {
		newCtx, cancel := context.WithTimeout(dialCtx, timeout)
		defer cancel()
		dialCtx = newCtx
	}

	conn, err := grpc.DialContext(dialCtx, "passthrough:///"+target.addressOrPod, opts...)
	if err != nil {
		return nil, fmt.Errorf("dialing %q (%q): %w", target.addressOrPod, target.node, err)
	}
	return conn, nil
}

func (r *Runtime) runBuiltInGadget(gadgetCtx runtime.GadgetContext, target target, allParams map[string]string) ([]byte, error) {
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
	client := api.NewBuiltInGadgetManagerClient(conn)

	runRequest := &api.BuiltInGadgetRunRequest{
		GadgetName:     gadgetCtx.GadgetDesc().Name(),
		GadgetCategory: gadgetCtx.GadgetDesc().Category(),
		Params:         allParams,
		Args:           gadgetCtx.Args(),
		Nodes:          nil,
		FanOut:         false,
		LogLevel:       uint32(gadgetCtx.Logger().GetLevel()),
		Timeout:        int64(gadgetCtx.Timeout()),
	}

	runClient, err := client.RunBuiltInGadget(connCtx)
	if err != nil && !errors.Is(err, context.Canceled) {
		return nil, err
	}

	controlRequest := &api.BuiltInGadgetControlRequest{Event: &api.BuiltInGadgetControlRequest_RunRequest{RunRequest: runRequest}}
	err = runClient.Send(controlRequest)
	if err != nil {
		return nil, err
	}

	parser := gadgetCtx.Parser()

	jsonHandler := func([]byte) {}
	jsonArrayHandler := func([]byte) {}

	if parser != nil {
		var enrichers []func(any) error
		ev := gadgetCtx.GadgetDesc().EventPrototype()
		if _, ok := ev.(operators.NodeSetter); ok {
			enrichers = append(enrichers, func(ev any) error {
				ev.(operators.NodeSetter).SetNode(target.node)
				return nil
			})
		}

		jsonHandler = parser.JSONHandlerFunc(enrichers...)
		jsonArrayHandler = parser.JSONHandlerFuncArray(target.node, enrichers...)
	}

	doneChan := make(chan error)

	var result []byte
	expectedSeq := uint32(1)

	go func() {
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
				if expectedSeq != ev.Seq {
					gadgetCtx.Logger().Warnf("%-20s | expected seq %d, got %d, %d messages dropped", target.node, expectedSeq, ev.Seq, ev.Seq-expectedSeq)
				}
				expectedSeq = ev.Seq + 1
				if len(ev.Payload) > 0 && ev.Payload[0] == '[' {
					jsonArrayHandler(ev.Payload)
					continue
				}
				jsonHandler(ev.Payload)
			case api.EventTypeGadgetResult:
				gadgetCtx.Logger().Debugf("%-20s | got result from server", target.node)
				result = ev.Payload
			case api.EventTypeGadgetJobID: // not needed right now
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
		// Send stop request
		gadgetCtx.Logger().Debugf("%-20s | sending stop request", target.node)
		controlRequest := &api.BuiltInGadgetControlRequest{Event: &api.BuiltInGadgetControlRequest_StopRequest{StopRequest: &api.BuiltInGadgetStopRequest{}}}
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
