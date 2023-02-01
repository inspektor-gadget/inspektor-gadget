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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type GadgetContext interface {
	ID() string
	Context() context.Context
	Gadget() gadgets.Gadget
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

	// GlobalParamDescs will return global params (required) for this operator
	GlobalParamDescs() params.ParamDescs

	// PerGadgetParams will return params (required) per gadget instance of the operator
	PerGadgetParams() params.ParamDescs

	// Dependencies can list other operators that this operator depends on
	Dependencies() []string

	// CanOperateOn should test whether the operator supports the given gadget. Init has not
	// necessarily been called at this point.
	CanOperateOn(gadgets.Gadget) bool

	// Init allows the operator to initialize itself
	Init(params *params.Params) error

	// Close allows the operator to clean up stuff prior to exiting
	Close() error

	// Instantiate is called before a gadget is run with this operator.
	// This must return something that implements OperatorInstance.
	// This is useful to create a context for an operator by wrapping it.
	// Params given here are the ones returned by PerGadgetParams()
	Instantiate(gadgetContext GadgetContext, gadgetInstance any, perGadgetParams *params.Params) (OperatorInstance, error)
}

type OperatorInstance interface {
	// Name returns the name of the operator instance
	Name() string

	// PreGadgetRun in called before a gadget is run
	PreGadgetRun() error

	// PostGadgetRun is called after a gadget is run
	PostGadgetRun() error

	// Enricher should return a function that is able to operator on the event ev and
	// call next afterwards.
	Enricher(next EnricherFunc) EnricherFunc

	// Deprecated: EnrichEvent
	EnrichEvent(ev any) error
}

type Operators []Operator

// ContainerInfoFromMountNSID is a typical kubernetes operator interface that adds node, pod, namespace and container
// information given the MountNSID
type ContainerInfoFromMountNSID interface {
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

func (e *operatorWrapper) Init(params *params.Params) (err error) {
	e.initOnce.Do(func() {
		err = e.Operator.Init(params)
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

// GlobalParamsCollection returns a collection of params of all registered operators
func GlobalParamsCollection() params.Collection {
	pc := make(params.Collection)
	for _, operator := range allOperators {
		pc[operator.Name()] = operator.GlobalParamDescs().ToParams()
	}
	return pc
}

// GetOperatorsForGadget checks which operators can work with the given gadgets and returns a collection
// of them
func GetOperatorsForGadget(gadget gadgets.Gadget) Operators {
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

// Init initializes all registered operators using their respective params
func (e Operators) Init(pc params.Collection) error {
	for _, operator := range e {
		err := operator.Init(pc[operator.Name()])
		if err != nil {
			return fmt.Errorf("initializing operator %q: %w", operator.Name(), err)
		}
	}
	return nil
}

// PerGadgetParamCollection returns a collection of parameters for all members of the operator collection
func (e Operators) PerGadgetParamCollection() params.Collection {
	pc := make(params.Collection)
	for _, operator := range e {
		pc[operator.Name()] = operator.PerGadgetParams().ToParams()
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
		operatorInstances = append(operatorInstances, oi)
	}

	for _, instance := range operatorInstances {
		if err := instance.PreGadgetRun(); err != nil {
			operatorInstances.Close()
			return nil, fmt.Errorf("pre gadget run on operator %q: %w", instance.Name(), err)
		}
	}

	return operatorInstances, nil
}

func (oi OperatorInstances) Close() error {
	// TODO: Handling errors?
	for _, instance := range oi {
		instance.PostGadgetRun()
	}
	return nil
}

// Deprecated: Enrich an event using all members of the operator collection
func (oi OperatorInstances) Enrich(ev any) error {
	var err error
	for _, operator := range oi {
		if err = operator.EnrichEvent(ev); err != nil {
			return fmt.Errorf("operator %q failed to enrich event %+v", operator.Name(), ev)
		}
	}
	return nil
}

func (oi OperatorInstances) Enricher(fn func(any) error) func(any) error {
	for i := len(oi) - 1; i >= 0; i-- {
		nfn := oi[i].Enricher(fn)
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
