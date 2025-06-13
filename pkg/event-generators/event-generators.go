// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eventgenerators

import (
	"fmt"
	"sort"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// Environment defines the environment in which the generator will run.
type Environment string

const (
	// EnvK8sNode is the environment for Kubernetes nodes. It will create a
	// static-Pod and then generate the events in the context of that Pod.
	// It expects to have write permissions to the /etc/kubernetes/manifests
	// directory, which is the default location for static Pods.
	EnvK8sNode Environment = "k8s-node"

	// EnvHost is the environment for the host. It will generate the events
	// directly from the IG process thus without any containerization.
	EnvHost Environment = "host"
)

func (e Environment) String() string {
	switch e {
	case EnvK8sNode:
		return "k8s-node"
	case EnvHost:
		return "host"
	default:
		return "unknown"
	}
}

// EnvironmentFromString converts a string to an Environment.
func EnvironmentFromString(env string) (Environment, error) {
	switch env {
	case "k8s-node":
		return EnvK8sNode, nil
	case "host":
		return EnvHost, nil
	default:
		return "", fmt.Errorf("unknown environment %q; valid environments: %v", env, []Environment{EnvK8sNode, EnvHost})
	}
}

func Environments() []string {
	return []string{EnvK8sNode.String(), EnvHost.String()}
}

// Generator is the interface each generator must implement.
type Generator interface {
	Generate() error
	Cleanup() error
}

// Factory produces a new EventGenerator.
type Factory func(logger logger.Logger, env Environment, count int, interval time.Duration, params map[string]string) (Generator, error)

var registry = make(map[string]Factory)

// Register makes a generator available under the given name.
// It's intended to be called from each generator’s init().
func Register(name string, factory Factory) {
	if _, dup := registry[name]; dup {
		panic("eventgenerator: Register called twice for " + name)
	}
	registry[name] = factory
}

// Generators returns the sorted list of registered generator names.
func Generators() []string {
	out := make([]string, 0, len(registry))
	for name := range registry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// New instantiates the named generator or returns an error if unknown.
func New(name string,
	logger logger.Logger,
	envStr string,
	count int,
	interval time.Duration,
	params map[string]string,
) (Generator, error) {
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf(
			"unknown generator type %q; valid types: %v",
			name, Generators(),
		)
	}
	env, err := EnvironmentFromString(envStr)
	if err != nil {
		return nil, fmt.Errorf("invalid environment %q: %w", envStr, err)
	}
	return factory(logger, env, count, interval, params)
}
