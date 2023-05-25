// Copyright 2019-2021 The Inspektor Gadget authors
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

package utils

import (
	"errors"
	"fmt"
)

// Gadget pod
var (
	ErrGadgetPodNotFound      = errors.New("gadget pod not found")
	ErrMultipleGadgetPodFound = errors.New("multiple gadget pods found")
)

// Kubernetes client

func WrapInErrSetupK8sClient(err error) error {
	return fmt.Errorf("setting up Kubernetes client: %w", err)
}

func WrapInErrListNodes(err error) error {
	return fmt.Errorf("listing nodes: %w", err)
}

func WrapInErrListPods(err error) error {
	return fmt.Errorf("listing pods: %w", err)
}

// Manager

func WrapInErrManagerInit(err error) error {
	return fmt.Errorf("initializing manager: %w", err)
}

func WrapInErrManagerCreateMountNsMap(err error) error {
	return fmt.Errorf("creating mountns map: %w", err)
}

// Parser

func WrapInErrParserCreate(err error) error {
	return fmt.Errorf("creating parser: %w", err)
}

// Gadget Tracers

func WrapInErrGadgetTracerCreateAndRun(err error) error {
	return fmt.Errorf("creating and running gadget tracer: %w", err)
}

// Gadget operations

func WrapInErrRunGadget(err error) error {
	return fmt.Errorf("running gadget: %w", err)
}

func WrapInErrRunGadgetOnNode(node string, err error) error {
	return fmt.Errorf("running gadget on node %q: %w", node, err)
}

func WrapInErrRunGadgetOnAllNode(err error) error {
	return fmt.Errorf("running gadget on all nodes: %w", err)
}

func WrapInErrStopGadget(err error) error {
	return fmt.Errorf("stopping gadget: %w", err)
}

func WrapInErrGenGadgetOutput(err error) error {
	return fmt.Errorf("generating gadget's output: %w", err)
}

func WrapInErrGetGadgetOutput(err error) error {
	return fmt.Errorf("getting gadget's output: %w", err)
}

func WrapInErrListGadgetTraces(err error) error {
	return fmt.Errorf("listing the running traces: %w", err)
}

// Arguments

func WrapInErrOutputModeNotSupported(mode string) error {
	return fmt.Errorf("%q output mode is not supported", mode)
}

func WrapInErrArgsNotSupported(args string) error {
	return fmt.Errorf("arguments not supported: %s", args)
}

func WrapInErrMissingArgs(args string) error {
	return fmt.Errorf("missing required arguments: %s", args)
}

func WrapInErrInvalidArg(arg string, err error) error {
	return fmt.Errorf("invalid argument '%s': %w", arg, err)
}

// JSON parsing

func WrapInErrUnmarshalOutput(err error, output string) error {
	return fmt.Errorf("unmarshaling output: %w\n%s", err, output)
}

func WrapInErrMarshalOutput(err error) error {
	return fmt.Errorf("marshaling output: %w", err)
}
