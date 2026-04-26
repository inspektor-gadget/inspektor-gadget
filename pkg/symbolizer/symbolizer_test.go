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

package symbolizer_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
	utils "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"

	// Register all symbolizer resolvers
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer/debuginfod"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer/otel"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer/symtab"
)

func TestSymbolizerCloseNoGoroutineLeak(t *testing.T) {
	utils.RequireRoot(t)

	tests := []struct {
		name string
		opts symbolizer.SymbolizerOptions
	}{
		{
			name: "symtab only",
			opts: symbolizer.SymbolizerOptions{
				UseSymtab: true,
			},
		},
		{
			name: "debuginfod only",
			opts: symbolizer.SymbolizerOptions{
				UseDebugInfodCache: true,
			},
		},
		{
			name: "symtab and debuginfod",
			opts: symbolizer.SymbolizerOptions{
				UseSymtab:          true,
				UseDebugInfodCache: true,
			},
		},
		{
			name: "otel-ebpf-profiler only",
			opts: symbolizer.SymbolizerOptions{
				UseOtelEbpfProfiler: true,
			},
		},
		{
			name: "all symbolizers",
			opts: symbolizer.SymbolizerOptions{
				UseSymtab:           true,
				UseDebugInfodCache:  true,
				UseOtelEbpfProfiler: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Let existing goroutines settle
			runtime.GC()
			time.Sleep(100 * time.Millisecond)

			before := runtime.NumGoroutine()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tt.opts.Context = ctx

			s, err := symbolizer.NewSymbolizer(tt.opts)
			require.NoError(t, err)
			require.NotNil(t, s)

			// Give background goroutines time to start
			time.Sleep(100 * time.Millisecond)

			s.Close()
			cancel()

			// Give goroutines time to stop
			time.Sleep(200 * time.Millisecond)
			runtime.GC()

			after := runtime.NumGoroutine()
			require.LessOrEqual(t, after, before+1,
				"goroutine leak detected: before=%d after=%d", before, after)
		})
	}
}
