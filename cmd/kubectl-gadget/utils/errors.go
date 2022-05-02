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
	return fmt.Errorf("failed to set up Kubernetes client: %w", err)
}

func WrapInErrListNodes(err error) error {
	return fmt.Errorf("failed to list nodes: %w", err)
}

// Gadget operations

func WrapInErrRunGadget(err error) error {
	return fmt.Errorf("failed to run gadget: %w", err)
}

func WrapInErrRunGadgetOnNode(node string, err error) error {
	return fmt.Errorf("failed to run gadget on node %q: %w", node, err)
}

func WrapInErrRunGadgetOnAllNode(err error) error {
	return fmt.Errorf("failed to run gadget on all nodes: %w", err)
}

func WrapInErrStopGadget(err error) error {
	return fmt.Errorf("failed to stop gadget: %w", err)
}

func WrapInErrGenGadgetOutput(err error) error {
	return fmt.Errorf("failed to generate gadget's output: %w", err)
}

func WrapInErrGetGadgetOutput(err error) error {
	return fmt.Errorf("failed to get gadget's output: %w", err)
}

func WrapInErrListGadgetTraces(err error) error {
	return fmt.Errorf("failed to list the running traces: %w", err)
}

// Arguments

var ErrJSONNotSupported = errors.New("JSON output format is not supported")

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
	return fmt.Errorf("failed to unmarshal output: %w\n%s", err, output)
}

func WrapInErrMarshalOutput(err error) error {
	return fmt.Errorf("failed to marshal output: %w", err)
}
