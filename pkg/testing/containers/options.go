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

package containers

import (
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

type cOptions struct {
	options      []testutils.Option
	cleanup      bool
	startAndStop bool
}

// ContainerOption is a function that modifies a ContainerSpec and exposes only
// few options from testutils.Option to the user.
type ContainerOption func(opts *cOptions)

func (o *cOptions) IsCleanup() bool {
	return o.cleanup
}

func (o *cOptions) IsStartAndStop() bool {
	return o.startAndStop
}

func WithContainerImage(image string) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithImage(image))
	}
}

func WithContainerSeccompProfile(profile string) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithSeccompProfile(profile))
	}
}

func WithContainerNamespace(namespace string) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithNamespace(namespace))
	}
}

func WithUseExistingNamespace() ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithUseExistingNamespace())
	}
}

func WithPrivileged() ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithPrivileged())
	}
}

func WithLimits(limits map[string]string) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithLimits(limits))
	}
}

func WithSysctls(sysctls map[string]string) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithSysctls(sysctls))
	}
}

func WithCleanup() ContainerOption {
	return func(opts *cOptions) {
		opts.cleanup = true
	}
}

func WithStartAndStop() ContainerOption {
	return func(opts *cOptions) {
		opts.startAndStop = true
	}
}

func WithWaitOrOomKilled() ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithWaitOrOomKilled())
	}
}

func WithExpectedExitCode(code int) ContainerOption {
	return func(opts *cOptions) {
		opts.options = append(opts.options, testutils.WithExpectedExitCode(code))
	}
}
