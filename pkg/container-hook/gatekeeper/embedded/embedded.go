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

// Package embedded optionally carries the container-hook gatekeeper binary
// (cmd/container-hook-gatekeeper) inside the binary that uses the container
// hook, so it runs without an install step and without re-executing its host
// binary. Build the gatekeeper for the target architecture into
// gatekeeper.bin in this directory and build with -tags gatekeeper_embed
// (`make ig` does both). Without the tag, Binary is nil.
package embedded

// BuildTag is the build tag that embeds gatekeeper.bin.
const BuildTag = "gatekeeper_embed"
