// Copyright 2026 The Inspektor Gadget authors
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

//go:build !cgo || !nvml

// This stub is built when:
//   - CGO is disabled (CGO_ENABLED=0), or
//   - The 'nvml' build tag is not set.
//
// In both cases the bridge cannot link against libnvidia-ml.so.1, so
// newRealPoller returns an error. The bridge's --mode=auto path
// translates that into "fall back to mock"; --mode=real treats it as
// a fatal startup error with a clear message.

package main

import (
	"errors"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gpu-ebpf-bridge/nvml"
)

func newRealPoller(libraryPath string) (nvml.Poller, error) {
	_ = libraryPath // unused in the stub; kept for signature parity
	return nil, errors.New("real NVML backend not compiled in (rebuild with -tags nvml and CGO_ENABLED=1)")
}

// Compile-time sanity: nvml.ErrNotAvailable is what callers check
// against to distinguish "no GPU on this node" from other errors.
var _ = nvml.ErrNotAvailable
