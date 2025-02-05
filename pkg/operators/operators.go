// Copyright 2022-2024 The Inspektor Gadget authors
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

package operators

import (
	"context"
	"fmt"
	"sync"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type GadgetContext interface {
	ID() string
	Name() string
	Context() context.Context
	GadgetDesc() gadgets.GadgetDesc
	Logger() logger.Logger

	Cancel()
	SerializeGadgetInfo() (*api.GadgetInfo, error)
	ImageName() string
	RegisterDataSource(datasource.Type, string) (datasource.DataSource, error)
	GetDataSources() map[string]datasource.DataSource
	SetVar(string, any)
	GetVar(string) (any, bool)
	Params() []*api.Param
	SetParams([]*api.Param)
	SetMetadata([]byte)
	OrasTarget() oras.ReadOnlyTarget
	IsRemoteCall() bool
}

type (
	EnricherFunc func(any) error
)

// MapPrefix is used to avoid clash with maps and other eBPF objects when added
// to gadget context.
const MapPrefix string = "map/"

type Operator interface {
	// Name must return a unique name for the operator
	Name() string

	// Description is an optional description to show to the user
	Description() string

	// GlobalParamDescs will return global params (required) for this operator
	GlobalParamDescs() params.ParamDescs

	// ParamDescs will return params (required) per gadget instance of the operator
	ParamDescs() params.ParamDescs

	// Dependencies can list other operators that this operator depends on
	Dependencies() []string

	// CanOperateOn should test whether the operator supports the given gadget. Init has not
	// necessarily been called at this point.
	CanOperateOn(gadgets.GadgetDesc) bool

	// Init allows the operator to initialize itself
	Init(params *params.Params) error

	// Close allows the operator to clean up stuff prior to exiting
	Close() error

	// Instantiate is called before a gadget is run with this operator.
	// This must return something that implements OperatorInstance.
	// This is useful to create a context for an operator by wrapping it.
	// Params given here are the ones returned by ParamDescs()
	Instantiate(gadgetCtx GadgetContext, gadgetInstance any, params *params.Params) (OperatorInstance, error)
}

type ImageOperator interface {
	Name() string

	// InstantiateImageOperator will be run to load information about a gadget and also to _possibly_
	// run the gadget afterward. It should only do things that are required to populate
	// DataSources and Params. It could use caching to speed things up, if necessary.
	InstantiateImageOperator(
		gadgetCtx GadgetContext,
		target oras.ReadOnlyTarget,
		descriptor ocispec.Descriptor,
		paramValues api.ParamValues,
	) (ImageOperatorInstance, error)
}

type ImageOperatorInstance interface {
	Name() string
	Prepare(gadgetCtx GadgetContext) error
	Start(gadgetCtx GadgetContext) error
	Stop(gadgetCtx GadgetContext) error
	ExtraParams(gadgetCtx GadgetContext) api.Params
}

type DataOperator interface {
	Name() string

	// Init allows the operator to initialize itself
	Init(params *params.Params) error

	// GlobalParams should return global params (required) for this operator; these are valid globally for the process
	GlobalParams() api.Params

	// InstanceParams should return parameters valid for a single gadget run
	InstanceParams() api.Params

	// InstantiateDataOperator should create a new (lightweight) instance for the operator that can read/write
	// from and to DataSources, register Params and read/write Variables; instanceParamValues can contain values for
	// both params defined by InstanceParams() as well as params defined by DataOperatorInstance.ExtraParams())
	InstantiateDataOperator(gadgetCtx GadgetContext, instanceParamValues api.ParamValues) (DataOperatorInstance, error)

	Priority() int
}

type DataOperatorInstance interface {
	Name() string
	Start(gadgetCtx GadgetContext) error
	Stop(gadgetCtx GadgetContext) error
}

type DataOperatorExtraParams interface {
	// ExtraParams can return dynamically created params; they are read after Prepare() has been called
	ExtraParams(gadgetCtx GadgetContext) api.Params
}

type PreStart interface {
	PreStart(gadgetCtx GadgetContext) error
}

type PreStop interface {
	PreStop(gadgetCtx GadgetContext) error
}

type PostStop interface {
	PostStop(gadgetCtx GadgetContext) error
}

type OperatorInstance interface {
	// Name returns the name of the operator instance
	Name() string

	// PreGadgetRun in called before a gadget is run
	PreGadgetRun() error

	// PostGadgetRun is called after a gadget is run
	PostGadgetRun() error

	// EnrichEvent enriches the given event with additional data
	EnrichEvent(ev any) error
}

type Operators []Operator

// ContainerInfoFromMountNSID is a typical kubernetes operator interface that adds node, pod, namespace and container
// information given the MountNSID
type ContainerInfoFromMountNSID interface {
	ContainerInfoSetters
	GetMountNSID() uint64
}

type ContainerInfoFromNetNSID interface {
	ContainerInfoSetters
	GetNetNSID() uint64
}

type ContainerInfoSetters interface {
	NodeSetter
	SetPodMetadata(types.Container)
	SetContainerMetadata(types.Container)
}

type NodeSetter interface {
	SetNode(string)
}

type ContainerInfoGetters interface {
	GetNode() string
	GetPod() string
	GetNamespace() string
	GetContainer() string
	GetContainerImageName() string
}

var allOperators = map[string]Operator{}

type operatorWrapper struct {
	Operator
	initOnce    sync.Once
	initialized bool
}

func (e *operatorWrapper) Init(params *params.Params) (err error) {
	e.initOnce.Do(func() {
		err = e.Operator.Init(params)
		e.initialized = true
	})
	return err
}

func GetRaw(name string) Operator {
	if op, ok := allOperators[name]; ok {
		return op.(*operatorWrapper).Operator
	}
	return nil
}

// Register adds a new operator to the registry
func Register(operator Operator) {
	if _, ok := allOperators[operator.Name()]; ok {
		panic(fmt.Errorf("operator already registered: %q", operator.Name()))
	}
	allOperators[operator.Name()] = &operatorWrapper{Operator: operator}
}

// GlobalParamsCollection returns a collection of params of all registered operators
func GlobalParamsCollection() params.Collection {
	pc := make(params.Collection)
	for _, operator := range allOperators {
		pc[operator.Name()] = operator.GlobalParamDescs().ToParams()
	}
	return pc
}

// GetAll returns all registered operators
func GetAll() Operators {
	operators := make(Operators, 0, len(allOperators))
	for _, op := range allOperators {
		operators = append(operators, op)
	}
	return operators
}

// GetOperatorsForGadget checks which operators can work with the given gadgets and returns a collection
// of them
func GetOperatorsForGadget(gadget gadgets.GadgetDesc) Operators {
	out := make(Operators, 0)
	for _, operator := range allOperators {
		if operator.CanOperateOn(gadget) {
			out = append(out, operator)
		}
	}
	out, err := SortOperators(out)
	if err != nil {
		panic(fmt.Sprintf("sorting operators: %v", err))
	}
	return out
}

// Init initializes all operators in the collection using their respective params
func (e Operators) Init(pc params.Collection) error {
	for _, operator := range e {
		err := operator.Init(pc[operator.Name()])
		if err != nil {
			return fmt.Errorf("initializing operator %q: %w", operator.Name(), err)
		}
	}
	return nil
}

// Close closes all operators in the collection; errors will be written to the log
func (e Operators) Close() {
	for _, operator := range e {
		err := operator.Close()
		if err != nil {
			log.Warnf("closing operator %q: %v", operator.Name(), err)
		}
	}
}

// ParamDescCollection returns a collection of parameter descriptors for all members of the operator collection
func (e Operators) ParamDescCollection() params.DescCollection {
	pc := make(params.DescCollection)
	for _, operator := range e {
		desc := operator.ParamDescs()
		pc[operator.Name()] = &desc
	}
	return pc
}

// ParamCollection returns a collection of parameters for all members of the operator collection
func (e Operators) ParamCollection() params.Collection {
	pc := make(params.Collection)
	for _, operator := range e {
		pc[operator.Name()] = operator.ParamDescs().ToParams()
	}
	return pc
}

type OperatorInstances []OperatorInstance

// Instantiate calls Instantiate on all operators and returns a collection of the results.
// It also calls PreGadgetRun on all instances.
func (e Operators) Instantiate(gadgetContext GadgetContext, trace any, perGadgetParamCollection params.Collection) (operatorInstances OperatorInstances, _ error) {
	operatorInstances = make([]OperatorInstance, 0, len(e))

	for _, operator := range e {
		oi, err := operator.Instantiate(gadgetContext, trace, perGadgetParamCollection[operator.Name()])
		if err != nil {
			return nil, fmt.Errorf("start trace on operator %q: %w", operator.Name(), err)
		}
		if oi == nil {
			// skip operators that opted out of handling the gadget
			continue
		}
		operatorInstances = append(operatorInstances, oi)
	}

	return operatorInstances, nil
}

func (oi OperatorInstances) PreGadgetRun() error {
	loadedInstances := make(OperatorInstances, 0, len(oi))
	for _, instance := range oi {
		if err := instance.PreGadgetRun(); err != nil {
			loadedInstances.PostGadgetRun()
			return fmt.Errorf("pre gadget run on operator %q: %w", instance.Name(), err)
		}
		loadedInstances = append(loadedInstances, instance)
	}
	return nil
}

func (oi OperatorInstances) PostGadgetRun() error {
	// TODO: Handling errors?
	for _, instance := range oi {
		instance.PostGadgetRun()
	}
	return nil
}

// Enrich an event using all members of the operator collection
func (oi OperatorInstances) Enrich(ev any) error {
	var err error
	for _, operator := range oi {
		if err = operator.EnrichEvent(ev); err != nil {
			return fmt.Errorf("operator %q failed to enrich event %+v", operator.Name(), ev)
		}
	}
	return nil
}

// SortOperators builds a dependency tree of the given operator collection and sorts them by least dependencies first
// Returns an error, if there are loops or missing dependencies
func SortOperators(operators Operators) (Operators, error) {
	// Create a map to store the incoming edge count for each element
	incomingEdges := make(map[string]int)
	for _, e := range operators {
		// Initialize the incoming edge count for each element to zero
		incomingEdges[e.Name()] = 0
	}

	// Build the graph by adding an incoming edge for each dependency
	for _, e := range operators {
		for _, d := range e.Dependencies() {
			incomingEdges[d]++
		}
	}

	// Check if all dependencies are in operators
outerLoop:
	for opName := range incomingEdges {
		for _, e := range operators {
			if opName == e.Name() {
				continue outerLoop
			}
		}
		return nil, fmt.Errorf("dependency %q is not available in operators", opName)
	}

	// Initialize the queue with all the elements that have zero incoming edges
	var queue []string
	for _, e := range operators {
		if incomingEdges[e.Name()] == 0 {
			queue = append(queue, e.Name())
		}
	}

	// Initialize the result slice
	var result Operators

	// Initialize the visited set
	visited := make(map[string]bool)

	// Process the queue
	for len(queue) > 0 {
		// Pop an element from the queue
		n := queue[0]
		queue = queue[1:]

		// Add the element to the visited set
		visited[n] = true

		// Prepend the element to the result slice
		for _, s := range operators {
			if s.Name() == n {
				result = append(Operators{s}, result...)
				break
			}
		}

		// Decrement the incoming edge count for each of the element's dependencies
		for _, d := range result[0].Dependencies() {
			incomingEdges[d]--
			// If a dependency's incoming edge count becomes zero, add it to the queue
			if incomingEdges[d] == 0 {
				queue = append(queue, d)
			}
			// If a dependency is already in the visited set, there is a cycle
			if visited[d] {
				return nil, fmt.Errorf("dependency cycle detected")
			}
		}
	}

	// Return an error if there are any unvisited elements, indicating that there is a cycle in the dependencies
	for _, e := range operators {
		if !visited[e.Name()] {
			return nil, fmt.Errorf("dependency cycle detected")
		}
	}

	return result, nil
}
