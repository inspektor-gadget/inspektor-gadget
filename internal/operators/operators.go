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

package operators

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runner interface {
	ID() string
	Parser() parser.Parser
	Gadget() gadgets.Gadget
	Context() context.Context
	Operators() Operators
	Logger() logger.Logger
}

type (
	EnricherFunc func(any) error
)

var ErrAsync = errors.New("async")

type Operator interface {
	// Name must return a unique name for the operator
	Name() string

	// Description is an optional description to show to the user
	Description() string

	// GlobalParams will return global params (required) for this operator
	GlobalParams() *params.Params

	// NewGadgetParams returns a new instance of the gadget parameters. These hold
	// also default values, descriptions, validators and so on. Used whenever a
	// gadget is called somehow. Auto-creates parameters for cobra as well.
	NewGadgetParams(id string) *params.Params

	// Dependencies can list other allOperators that this operator depends on
	Dependencies() []string

	// CanOperateOn should test whether the operator supports the given gadget. Init has not
	// necessarily been called at this point.
	CanOperateOn(gadgets.Gadget) bool

	// Init allows the operator to initialize itself
	Init() error

	// Close allows the operator to clean up stuff prior to exiting
	Close() error

	// Instantiate is called before a gadget is run (before PreGadgetRun) with this operator
	// This must return something that implements operator as well.
	// This is useful to create a context for an operator by wrapping it.
	Instantiate(runner Runner, gadgetInstance any) (OperatorInstance, error)
}

type OperatorInstance interface {
	// PreGadgetRun is called before a gadget is started but after all allOperators have been initialized
	PreGadgetRun() error

	// PostGadgetRun is called on the operator that was returned from PrepareTrace after a
	// gadget was stopped
	PostGadgetRun() error

	// Enricher should return a function that is able to operator on the event ev and
	// call next afterwards.
	Enricher(next EnricherFunc) EnricherFunc

	// Deprecated: EnrichEvent
	EnrichEvent(ev any) error
}

type operatorInterfaces struct {
	Operator
	OperatorInstance
}

type Operators []operatorInterfaces

// KubernetesFromMountNSID is a typical kubernetes operator interface that adds node, pod, namespace and container
// information given the MountNSID
type KubernetesFromMountNSID interface {
	ContainerInfoSetters
	GetMountNSID() uint64
}

type ContainerInfoSetters interface {
	SetContainerInfo(pod, namespace, container string)
	SetNode(string)
}

var allOperators = map[string]Operator{}

type operatorWrapper struct {
	Operator
	initOnce    sync.Once
	initialized bool
}

func (e *operatorWrapper) Init() (err error) {
	e.initOnce.Do(func() {
		err = e.Operator.Init()
		e.initialized = true
	})
	return err
}

// Register adds a new operator to the registry
func Register(operator Operator) {
	if _, ok := allOperators[operator.Name()]; ok {
		panic(fmt.Errorf("operator already registered: %q", operator.Name()))
	}
	allOperators[operator.Name()] = operator
}

// GlobalParamCollection returns a collection of params of all registered allOperators
func GlobalParamCollection() params.Collection {
	pc := make(params.Collection)
	for _, operator := range allOperators {
		pc[operator.Name()] = operator.GlobalParams()
	}
	return pc
}

// GetOperatorsForGadget checks which allOperators can work with the given gadgets and returns a collection
// of them
func GetOperatorsForGadget(gadget gadgets.Gadget) Operators {
	out := make(Operators, 0)
	for _, operator := range allOperators {
		if operator.CanOperateOn(gadget) {
			out = append(out, operatorInterfaces{
				Operator: operator,
			})
		}
	}
	out, err := SortOperators(out)
	if err != nil {
		panic(fmt.Sprintf("sorting allOperators: %v", err))
	}
	return out
}

// Init initializes all registered allOperators using their respective params
func (e Operators) Init() error {
	for _, operator := range e {
		err := operator.Init()
		if err != nil {
			return fmt.Errorf("initializing operator %q: %w", operator.Name(), err)
		}
	}
	return nil
}

// NewGadgetParamsCollection returns a collection of parameters for all members of the operator collection
func (e Operators) NewGadgetParamsCollection(id string) params.Collection {
	pc := make(params.Collection)
	for _, operator := range e {
		pc[operator.Name()] = operator.NewGadgetParams(id)
	}
	return pc
}

// PreGadgetRun calls PreGadgetRun on all members of the operator collection and replaces them with the returned
// instance
func (e Operators) PreGadgetRun(runner Runner, trace any) error {
	for i, operator := range e {
		operatorInstance, err := operator.Instantiate(runner, trace)
		if err != nil {
			return fmt.Errorf("start trace on operator %q: %w", operator.Name(), err)
		}
		e[i].OperatorInstance = operatorInstance
	}
	for _, operator := range e {
		err := operator.PreGadgetRun()
		if err != nil {
			return fmt.Errorf("start trace on operator %q: %w", operator.Name(), err)
		}
	}
	return nil
}

func (e Operators) PostGadgetRun() error {
	// TODO: Handling errors?
	for _, operator := range e {
		operator.PostGadgetRun()
	}
	return nil
}

// Deprecated: Enrich an event using all members of the operator collection
func (e Operators) Enrich(ev any) error {
	var err error
	for _, operator := range e {
		if err = operator.EnrichEvent(ev); err != nil {
			return fmt.Errorf("operator %q failed to enrich event %+v", operator.Name(), ev)
		}
	}
	return nil
}

func (e Operators) Enricher(fn func(any) error) func(any) error {
	for i := len(e) - 1; i >= 0; i-- {
		nfn := e[i].Enricher(fn)
		if nfn != nil {
			fn = nfn
		}
	}
	return fn
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

type OperatorWithGadgetParams struct {
	gadgetParamsDescs      *params.ParamDescs
	gadgetParamsCollection params.Collection
}

func NewOperatorWithGadgetParams(descs *params.ParamDescs) *OperatorWithGadgetParams {
	if descs == nil {
		descs = &params.ParamDescs{}
	}
	return &OperatorWithGadgetParams{
		gadgetParamsDescs:      descs,
		gadgetParamsCollection: make(params.Collection),
	}
}

func (g *OperatorWithGadgetParams) NewGadgetParams(id string) *params.Params {
	if _, ok := g.gadgetParamsCollection[id]; ok {
		return nil
	}
	g.gadgetParamsCollection[id] = g.gadgetParamsDescs.ToParams()
	return g.gadgetParamsCollection[id]
}

func (g *OperatorWithGadgetParams) GetGadgetParams(id string) *params.Params {
	return g.gadgetParamsCollection[id]
}
