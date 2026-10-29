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
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// TestLegacyEncodingCompat is the regression test for the permanent backward
// compatibility guarantee: a new ig must keep loading pre-built gadget images
// that carry only the legacy "___"-style magic-global symbols and NO ig:* decl
// tags.
//
// testdata/legacy_encoding/program.o is a hand-written fixture frozen in the
// OLD encoding (see its program.bpf.c). The test loads it and drives the same
// populate* helpers that the legacy prefix walk in analyze() invokes, asserting
// that the legacy symbols are still decoded into params, variables and tracer
// maps.
func TestLegacyEncodingCompat(t *testing.T) {
	f, err := os.Open("testdata/legacy_encoding/program.o")
	require.NoError(t, err, "opening legacy fixture")
	t.Cleanup(func() { f.Close() })

	spec, err := ebpf.LoadCollectionSpecFromReader(f)
	require.NoError(t, err, "loading legacy fixture spec")
	require.NotNil(t, spec.Types, "fixture must carry BTF")

	// Sanity: the fixture must genuinely be old-encoding, i.e. carry the legacy
	// marker symbols and NOT a single ig:* decl tag. Otherwise this would test
	// the new path by accident.
	assertNoIGTags(t, spec)
	for _, marker := range []string{
		paramPrefix + "myparam",    // gadget_param_myparam
		tracerMapPrefix + "events", // gadget_map_tracer_events
	} {
		var v *btf.Var
		assert.NoErrorf(t, spec.Types.TypeByName(marker, &v),
			"legacy marker %q missing from fixture", marker)
	}
	// The gadget_var_ variable is the real (const volatile) variable, not a
	// throwaway marker.
	assert.True(t, strings.HasPrefix("gadget_var_myvar", varPrefix),
		"gadget_var_ prefix constant changed; would break old-image compat")

	i := &ebpfInstance{
		logger:         logger.DefaultLogger(),
		collectionSpec: spec,
		config:         viper.New(),
		params:         map[string]*param{},
		vars:           map[string]*ebpfVar{},
		gadgetCtx:      gadgetcontext.New(context.Background(), "legacy-compat-test"),
	}

	// GADGET_PARAM(myparam): the walk trims the gadget_param_ marker and calls
	// populateParam with the real variable name.
	require.NoError(t, i.populateParam(nil, "myparam"), "populateParam")
	require.Contains(t, i.params, "myparam", "legacy param not registered")

	// gadget_var_myvar: the walk trims the gadget_var_ prefix and passes the
	// real btf.Var plus the trimmed name.
	var myvar *btf.Var
	require.NoError(t, spec.Types.TypeByName("gadget_var_myvar", &myvar))
	require.NoError(t, i.populateVar(myvar, "myvar"), "populateVar")
	require.Contains(t, i.vars, "myvar", "legacy variable not registered")

	// GADGET_TRACER_MAP(events): fixTracerMap must find the ring buffer map by
	// its name (and would downgrade it to a perf event array on kernels without
	// ring buffers).
	require.NoError(t, i.fixTracerMap(nil, "events"), "fixTracerMap")
	require.Contains(t, spec.Maps, "events", "tracer map missing")
}

// assertNoIGTags fails the test if any Var, Func or Map in the spec carries an
// ig:* decl tag.
func assertNoIGTags(t *testing.T, spec *ebpf.CollectionSpec) {
	t.Helper()
	for typ, err := range spec.Types.All() {
		require.NoError(t, err)
		switch v := typ.(type) {
		case *btf.Var:
			for _, tag := range v.Tags {
				assert.Falsef(t, strings.HasPrefix(tag, igTagPrefix),
					"unexpected ig tag %q on var %q", tag, v.Name)
			}
		case *btf.Func:
			for _, tag := range v.Tags {
				assert.Falsef(t, strings.HasPrefix(tag, igTagPrefix),
					"unexpected ig tag %q on func %q", tag, v.Name)
			}
		}
	}
	for name, ms := range spec.Maps {
		for _, tag := range ms.Tags {
			assert.Falsef(t, strings.HasPrefix(tag, igTagPrefix),
				"unexpected ig tag %q on map %q", tag, name)
		}
	}
}
