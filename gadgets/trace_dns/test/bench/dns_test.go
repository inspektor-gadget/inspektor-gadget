// Copyright 2019-2024 The Inspektor Gadget authors
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

package tests

import (
	"fmt"
	"testing"

	bench "github.com/inspektor-gadget/inspektor-gadget/benchmarks"
)

const (
	DefaultServerImage = "ghcr.io/mauriciovasquezbernal/bench"
	DefaultClientImage = "ghcr.io/mauriciovasquezbernal/bench"
)

func TestTraceDNS(t *testing.T) {
	rps := []any{1024 /*1024, 2048, 4096, 8192, 16384 , 32768, 65536*/}

	c := &bench.GadgetBenchTest{
		Gadget:         "trace_dns",
		ServerImage:    DefaultServerImage,
		GeneratorImage: DefaultClientImage,
		TestConfs:      rps,
		ServerCmd: func(rps any) string {
			return "/bench --events=dns-server"
		},
		GeneratorCmd: func(serverIP string, a any) string {
			return fmt.Sprintf("/bench --events=dns:server=%s:5353 --events-per-second=%d", serverIP, a)
		},
	}

	bench.RunGadgetBenchmark(t, c)
}
