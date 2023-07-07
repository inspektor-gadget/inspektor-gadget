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

package testutils

import "context"

const (
	DefaultContainerImage    = "docker.io/library/busybox"
	DefaultContainerImageTag = "latest"
)

type Option func(*containerOptions)

type containerOptions struct {
	ctx            context.Context
	image          string
	imageTag       string
	seccompProfile string
	wait           bool
	logs           bool
	removal        bool
}

func defaultContainerOptions() *containerOptions {
	return &containerOptions{
		ctx:      context.TODO(),
		image:    DefaultContainerImage,
		imageTag: DefaultContainerImageTag,
		logs:     true,
		wait:     true,
		removal:  true,
	}
}

func WithContext(ctx context.Context) Option {
	return func(opts *containerOptions) {
		opts.ctx = ctx
	}
}

func WithImage(image string) Option {
	return func(opts *containerOptions) {
		opts.image = image
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

func WithoutWait() Option {
	return func(opts *containerOptions) {
		opts.wait = false
	}
}

func WithoutRemoval() Option {
	return func(opts *containerOptions) {
		opts.removal = false
	}
}

func WithoutLogs() Option {
	return func(opts *containerOptions) {
		opts.logs = false
	}
}
