//go:build linux
// +build linux

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

package tracer

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/test"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
)

type collectorFunc func(config *Config, enricher gadgets.DataEnricher) ([]*processcollectortypes.Event, error)

func BenchmarkEBPFTracer(b *testing.B) {
	benchmarkTracer(b, runeBPFCollector)
}

func BenchmarkProcfsTracer(b *testing.B) {
	benchmarkTracer(b, runProcfsCollector)
}

func benchmarkTracer(b *testing.B, runCollector collectorFunc) {
	utilstest.RequireRoot(b)

	for n := 0; n < b.N; n++ {
		_, err := runCollector(&Config{}, nil)
		if err != nil {
			b.Fatalf("benchmarking collector: %s", err)
		}
	}
}
