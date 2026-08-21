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

package ebpfoperator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

func TestResolvePerfBufferPages(t *testing.T) {
	instance := &ebpfInstance{
		logger: logger.DefaultLogger(),
	}

	t.Run("nil datasource", func(t *testing.T) {
		pages := instance.resolvePerfBufferPages(nil)
		require.Equal(t, gadgets.PerfBufferPages, pages)
	})

	t.Run("missing annotation", func(t *testing.T) {
		gadgetCtx := gadgetcontext.New(context.Background(), "test")
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)

		pages := instance.resolvePerfBufferPages(ds)
		require.Equal(t, gadgets.PerfBufferPages, pages)
	})

	t.Run("valid annotation", func(t *testing.T) {
		gadgetCtx := gadgetcontext.New(context.Background(), "test")
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationTracerPerfBufferPages, "128")

		pages := instance.resolvePerfBufferPages(ds)
		require.Equal(t, 128, pages)
	})

	t.Run("invalid annotation non-number", func(t *testing.T) {
		gadgetCtx := gadgetcontext.New(context.Background(), "test")
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationTracerPerfBufferPages, "invalid")

		pages := instance.resolvePerfBufferPages(ds)
		require.Equal(t, gadgets.PerfBufferPages, pages)
	})

	t.Run("invalid annotation negative or zero", func(t *testing.T) {
		gadgetCtx := gadgetcontext.New(context.Background(), "test")
		ds, err := gadgetCtx.RegisterDataSource(datasource.TypeSingle, "test")
		require.NoError(t, err)
		ds.AddAnnotation(AnnotationTracerPerfBufferPages, "-10")

		pages := instance.resolvePerfBufferPages(ds)
		require.Equal(t, gadgets.PerfBufferPages, pages)
	})
}
