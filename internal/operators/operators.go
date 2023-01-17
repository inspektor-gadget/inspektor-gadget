// Copyright 2022 The Inspektor Gadget authors
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

	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/internal/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

type Runner interface {
	ID() string
	Columns() columnhelpers.Columns
	Gadget() gadgets.Gadget
	Context() context.Context
	Operators() Operators
	Logger() logger.Logger
}

type Operator interface {
	// Name must return a unique name for the operator
	Name() string

	// Description is an optional description to show to the user
	Description() string

	// Params will return global params (required) for this operator
	Params() params.Params

	// PerGadgetParams will return params (required) per gadget instance of the operator
	PerGadgetParams() params.Params

	// Dependencies can list other operators that this operator depends on
	Dependencies() []string

	// CanOperateOn should test whether the operator supports the given gadget. Init has not
	// necessarily been called at this point.
	CanOperateOn(gadgets.Gadget) bool

	// Init allows the operator to initialize itself
	Init(params params.Params) error

	// Cleanup allows the operator to clean up stuff prior to exiting
	Cleanup() error

	// PreGadgetRun is called before a gadget is started; the operator must return something that implements operator
	// This is useful to create a context for an operator by wrapping it.
	// Params given here are the ones returned by PerGadgetParams()
	PreGadgetRun(Runner, any, params.Params) (Operator, error)

	// PostGadgetRun is called on the operator that was returned from PrepareTrace after a
	// gadget was stopped
	PostGadgetRun() error

	// EnrichEvent is called on the operator returned by StartTrace and should perform
	// the actual enrichment
	EnrichEvent(any) error
}

type Operators []Operator

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

var operators = map[string]Operator{}

type operatorWrapper struct {
	Operator
	initOnce    sync.Once
	initialized bool
}

func (e *operatorWrapper) Init(params params.Params) (err error) {
	e.initOnce.Do(func() {
		err = e.Operator.Init(params)
		e.initialized = true
	})
	return err
}

// RegisterOperator adds a new operator to the registry
func RegisterOperator(operator Operator) {
	if _, ok := operators[operator.Name()]; ok {
		panic(fmt.Errorf("operator already registered: %q", operator.Name()))
	}
	operators[operator.Name()] = operator
}

// OperatorsParamsCollection returns a collection of params of all registered operators
func OperatorsParamsCollection() params.ParamsCollection {
	pc := make(params.ParamsCollection)
	for _, operator := range operators {
		pc[operator.Name()] = operator.Params()
	}
	return pc
}

// GetOperatorsForGadget checks which operators can work with the given gadgets and returns a collection
// of them
func GetOperatorsForGadget(gadget gadgets.Gadget) Operators {
	out := make(Operators, 0)
	for _, e := range operators {
		if e.CanOperateOn(gadget) {
			out = append(out, e)
		}
	}
	out, err := SortOperators(out)
	if err != nil {
		panic(fmt.Sprintf("sorting operators: %v", err))
	}
	return out
}

// InitAll initialized all registered operators using their respective params
func (e Operators) InitAll(pc params.ParamsCollection) error {
	for _, operator := range e {
		err := operator.Init(pc[operator.Name()])
		if err != nil {
			return fmt.Errorf("initializing operator %q: %w", operator.Name(), err)
		}
	}
	return nil
}

// PerGadgetParamCollection returns a collection of parameters for all members of the operator collection
func (e Operators) PerGadgetParamCollection() params.ParamsCollection {
	pc := make(params.ParamsCollection)
	for _, operator := range e {
		pc[operator.Name()] = operator.PerGadgetParams()
	}
	return pc
}

// PreGadgetRun calls PreGadgetRun on all members of the operator collection and replaces them with the returned
// instance
func (e Operators) PreGadgetRun(runner Runner, trace any, perGadgetParamCollection params.ParamsCollection) error {
	for i, operator := range e {
		ne, err := operator.PreGadgetRun(runner, trace, perGadgetParamCollection[operator.Name()])
		if err != nil {
			return fmt.Errorf("start trace on operator %q: %w", operator.Name(), err)
		}
		e[i] = ne
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

// Enrich an event using all members of the operator collection
func (e Operators) Enrich(ev any) {
	for _, operator := range e {
		operator.EnrichEvent(ev)
	}
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
