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

package testutils

import (
	"context"

	"github.com/docker/go-connections/nat"
)

const (
	DefaultContainerImage    = "ghcr.io/inspektor-gadget/ci/busybox"
	DefaultContainerImageTag = "latest"
)

type Option func(*containerOptions)

type containerOptions struct {
	ctx                  context.Context
	expectStartError     bool
	image                string
	imageTag             string
	mounts               []string
	seccompProfile       string
	namespace            string
	useExistingNamespace bool
	wait                 bool
	waitOrOomKilled      bool
	logs                 bool
	removal              bool
	portBindings         nat.PortMap
	privileged           bool
	limits               map[string]string
	expectedExitCode     *int

	// forceDelete is mostly used for debugging purposes, when a container
	// fails to be deleted and we want to force it.
	forceDelete bool
}

func defaultContainerOptions() *containerOptions {
	return &containerOptions{
		ctx:                  context.TODO(),
		image:                DefaultContainerImage,
		imageTag:             DefaultContainerImageTag,
		logs:                 true,
		wait:                 true,
		removal:              true,
		useExistingNamespace: false,
	}
}

func WithContext(ctx context.Context) Option {
	return func(opts *containerOptions) {
		opts.ctx = ctx
	}
}

func WithExpectStartError() Option {
	return func(opts *containerOptions) {
		opts.expectStartError = true
	}
}

func WithExpectedExitCode(code int) Option {
	return func(opts *containerOptions) {
		opts.expectedExitCode = &code
	}
}

func WithImage(image string) Option {
	return func(opts *containerOptions) {
		opts.image = image
	}
}

func WithBindMounts(mounts []string) Option {
	return func(opts *containerOptions) {
		opts.mounts = mounts
	}
}

func WithImageTag(tag string) Option {
	return func(opts *containerOptions) {
		opts.imageTag = tag
	}
}

func WithSeccompProfile(profile string) Option {
	return func(opts *containerOptions) {
		opts.seccompProfile = profile
	}
}

// WithNamespace sets the namespace of the container runtime
func WithNamespace(namespace string) Option {
	return func(opts *containerOptions) {
		opts.namespace = namespace
	}
}

func WithUseExistingNamespace() Option {
	return func(opts *containerOptions) {
		opts.useExistingNamespace = true
	}
}

func WithoutWait() Option {
	return func(opts *containerOptions) {
		opts.wait = false
	}
}

func WithWaitOrOomKilled() Option {
	return func(opts *containerOptions) {
		opts.waitOrOomKilled = true
	}
}

func WithoutLogs() Option {
	return func(opts *containerOptions) {
		opts.logs = false
	}
}

func WithPrivileged() Option {
	return func(opts *containerOptions) {
		opts.privileged = true
	}
}

// withoutRemoval is only used internally. If an external caller wants to run a
// container without removal, they should use the Start() method instead of
// Run().
func withoutRemoval() Option {
	return func(opts *containerOptions) {
		opts.removal = false
	}
}

// WithPortBindings sets the exposed ports of the container
func WithPortBindings(portBindings nat.PortMap) Option {
	return func(opts *containerOptions) {
		opts.portBindings = portBindings
	}
}

// WithForceDelete is mostly used for debugging purposes, when a container
// fails to be deleted and we want to force it.
func WithForceDelete() Option {
	return func(opts *containerOptions) {
		opts.forceDelete = true
	}
}

// WithLimits sets the resource limits of the container
func WithLimits(limits map[string]string) Option {
	return func(opts *containerOptions) {
		opts.limits = limits
	}
}
